use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn resolve(endpoint: &str, ips: &[&str]) -> Result<PinnedCollector, CollectorRequestError> {
    let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
    resolve_with(endpoint, |_, _| async { Ok(ips) }).await
}

#[tokio::test]
async fn public_https_addresses_are_accepted_and_keep_hostname_port_path_query() {
    let pin = resolve(
        "https://collector.example:8443/custom/metrics?tenant=one%2Ftwo",
        &["8.8.8.8", "2606:4700:4700::1111"],
    )
    .await
    .unwrap();
    assert_eq!(pin.url.host_str(), Some("collector.example"));
    assert_eq!(pin.url.path(), "/custom/metrics");
    assert_eq!(pin.url.query(), Some("tenant=one%2Ftwo"));
    assert_eq!(
        pin.addrs,
        vec![
            "8.8.8.8:8443".parse().unwrap(),
            "[2606:4700:4700::1111]:8443".parse().unwrap()
        ]
    );
}

#[tokio::test]
async fn unsafe_or_mixed_dns_rejects_every_attempt() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "169.254.1.2",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "::1",
        "::",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "2001::1",
        "2001:2::1",
        "2002:0808:0808::1",
        "2001:db8::1",
        "3fff::1",
        "64:ff9b::808:808",
    ] {
        assert!(
            resolve("https://collector.example/v1/metrics", &[ip])
                .await
                .is_err(),
            "accepted {ip}"
        );
        // Both orders: a safe first result must not short-circuit validation.
        for ips in [["8.8.8.8", ip], [ip, "8.8.8.8"]] {
            assert!(
                resolve("https://collector.example/v1/metrics", &ips)
                    .await
                    .is_err()
            );
        }
    }
    // The canonical classifier accepts mapped public IPv4; do not invent a
    // different IPv6 policy in this exporter.
    assert!(
        resolve("https://collector.example", &["::ffff:8.8.8.8"])
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn literal_ips_use_the_same_classifier_without_dns() {
    for host in [
        "8.8.8.8",
        "[2606:4700:4700::1111]",
        "[::ffff:8.8.8.8]",
        "127.0.0.1",
        "[::1]",
    ] {
        let pin = resolve_with(&format!("https://{host}/v1/metrics"), |_, _| async {
            panic!("literal address must not use DNS");
        })
        .await
        .unwrap();
        assert_eq!(pin.addrs.len(), 1);
        assert_eq!(pin.addrs[0].port(), 443);
    }
    for host in [
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "[fc00::1]",
        "[2002:0808:0808::1]",
        "[::ffff:127.0.0.1]",
    ] {
        assert!(resolve(&format!("https://{host}/"), &[]).await.is_err());
    }
}

#[tokio::test]
async fn loopback_test_hosts_require_exclusively_loopback_resolution() {
    for scheme in ["http", "https"] {
        let endpoint = format!("{scheme}://localhost:4318/v1/metrics");
        assert!(resolve(&endpoint, &["127.0.0.1", "::1"]).await.is_ok());
        for ips in [
            vec!["8.8.8.8"],
            vec!["10.0.0.1"],
            vec!["127.0.0.1", "8.8.8.8"],
            vec!["::ffff:127.0.0.1"],
        ] {
            assert!(resolve(&endpoint, &ips).await.is_err());
        }
        for host in ["127.0.0.1", "[::1]"] {
            assert!(
                resolve(&format!("{scheme}://{host}:4318/"), &[])
                    .await
                    .is_ok()
            );
        }
        assert!(
            resolve(&format!("{scheme}://public.example/"), &["127.0.0.1"])
                .await
                .is_err()
        );
        assert!(
            resolve(&format!("{scheme}://dev.localhost/"), &["127.0.0.1"])
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn invalid_structure_never_resolves() {
    for endpoint in [
        "http://public.example/",
        "http://10.0.0.1/",
        "http://[fc00::1]/",
        "https://user:password@collector.example/",
        "https://collector.example/#fragment",
        "https://collector.example:0/",
        "https://collector.example:65536/",
        "https:///",
        "ftp://collector.example/",
    ] {
        assert!(
            resolve_with(endpoint, |_, _| async {
                panic!("invalid URL reached DNS");
            })
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn resolution_failures_are_privacy_safe() {
    let endpoint = "https://sensitive.example/secret?token=secret-query";
    let errors = [
        resolve(endpoint, &[]).await.err().unwrap(),
        resolve_with(endpoint, |_, _| async {
            Err(std::io::Error::other(
                "sensitive.example secret-query 127.0.0.1 bearer-secret",
            ))
        })
        .await
        .err()
        .unwrap(),
        resolve(endpoint, &["127.0.0.1"]).await.err().unwrap(),
    ];
    for error in errors {
        assert_eq!(error.to_string(), "collector request failed");
        assert_eq!(format!("{error:?}"), "CollectorRequestError");
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn resolution_is_deadline_bound() {
    let start = tokio::time::Instant::now();
    assert!(
        resolve_with("https://collector.example/", |_, _| async {
            std::future::pending().await
        })
        .await
        .is_err()
    );
    assert_eq!(start.elapsed(), CONNECT_TIMEOUT);
}

#[tokio::test]
async fn every_attempt_resolves_fresh_and_checks_host_and_port() {
    let calls = AtomicUsize::new(0);
    let resolver = |host: String, port| {
        assert_eq!(host, "collector.example");
        assert_eq!(port, 8443);
        let call = calls.fetch_add(1, Ordering::SeqCst);
        async move {
            Ok(vec![
                if call == 0 { "8.8.8.8" } else { "127.0.0.1" }
                    .parse()
                    .unwrap(),
            ])
        }
    };
    assert!(
        resolve_with("https://collector.example:8443/", &resolver)
            .await
            .is_ok()
    );
    assert!(
        resolve_with("https://collector.example:8443/", &resolver)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

struct ForbiddenDns(Arc<AtomicUsize>);

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

        // The proxy has closed. A new connection must fail, even though a
        // direct origin listener is reachable and NO_PROXY matches everything.
        let client = pin.build_client().unwrap();
        assert!(client.post(pin.url).send().await.is_err());
        return;
    }

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
                return;
            }
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
                        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
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
        });
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "collector_host_safety::tests::socks5_pins_dns_fail_closed",
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
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err(),
            "explicit proxy failure must not dial the origin directly"
        );
    }
}

impl reqwest::dns::Resolve for ForbiddenDns {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(std::io::Error::other("second DNS lookup").into()) })
    }
}

#[tokio::test]
async fn reqwest_uses_only_pinned_addresses_and_ignores_proxies() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let pin = resolve(
        &format!("http://localhost:{}/metrics?exact=one%2Ftwo", addr.port()),
        &["127.0.0.1"],
    )
    .await
    .unwrap();
    let client = pin
        .build_client_from(
            reqwest::Client::builder()
                .dns_resolver(Arc::new(ForbiddenDns(calls.clone())))
                .proxy(
                    reqwest::Proxy::all(format!("http://{}", proxy.local_addr().unwrap())).unwrap(),
                ),
        )
        .unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut buf = [0; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(bytes).unwrap().to_lowercase();
        assert!(headers.starts_with("post /metrics?exact=one%2ftwo http/1.1\r\n"));
        assert!(headers.contains(&format!("host: localhost:{}\r\n", addr.port())));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    assert!(
        client
            .post(pin.url)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    server.await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "reqwest must not resolve again"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), proxy.accept())
            .await
            .is_err()
    );
}
