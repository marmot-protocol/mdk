use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn resolve(endpoint: &str, ips: &[&str]) -> Result<PinnedCollector, CollectorRequestError> {
    let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
    resolve_with(endpoint, |_, _| async { Ok(ips) }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
