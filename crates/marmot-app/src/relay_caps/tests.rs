use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// strfry's NIP-11 document, trimmed to the fields the caps read.
const STRFRY_NIP11: &str = r#"{"name":"strfry","supported_nips":[1,2,4,9,11,22,28,40,70,77],"limitation":{"max_limit":500}}"#;

enum Reply {
    Document {
        status: u16,
        body: String,
    },
    /// Answers after a pause, so concurrent callers overlap.
    Slow {
        delay: Duration,
        body: String,
    },
    /// Accepts and never answers.
    Hang,
}

/// One local relay's HTTP side. Counts connections and keeps each request head.
struct DocumentServer {
    port: u16,
    connections: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
}

impl DocumentServer {
    async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let reply = Arc::new(reply);
        let (count, kept) = (connections.clone(), heads.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let (reply, kept) = (reply.clone(), kept.clone());
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0; 1024];
                    while !head.ends_with(b"\r\n\r\n") {
                        let Ok(read) = stream.read(&mut buf).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        head.extend_from_slice(&buf[..read]);
                    }
                    kept.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&head).into_owned());
                    let (status, body) = match reply.as_ref() {
                        Reply::Document { status, body } => (*status, body.clone()),
                        Reply::Slow { delay, body } => {
                            tokio::time::sleep(*delay).await;
                            (200, body.clone())
                        }
                        Reply::Hang => {
                            std::future::pending::<()>().await;
                            unreachable!()
                        }
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/nostr+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            port,
            connections,
            heads,
        }
    }

    fn relay(&self, path: &str) -> String {
        format!("ws://127.0.0.1:{}{path}", self.port)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn fetch_with(resolve: impl Fn(String) -> Vec<IpAddr> + Send + Sync + 'static) -> Nip11Fetch {
    // These fetches run without a `MarmotApp`, so hand in its proxy policy as its constructors
    // do; the collector helper builds no client before one is handed in.
    crate::collector_host_safety::hand_in_http_builder(crate::network_proxy::http_builder);
    let resolve = Arc::new(resolve);
    Nip11Fetch {
        resolver: Arc::new(move |host, _port| {
            let ips = resolve(host);
            Box::pin(async move { Ok(ips) })
        }),
        ..Nip11Fetch::default()
    }
}

/// A resolver that fails the test if asked: the gate must refuse first.
fn no_dns() -> Nip11Fetch {
    fetch_with(|host| panic!("resolved {host} for a relay the gate must refuse"))
}

async fn fetch(
    fetch: &Nip11Fetch,
    endpoint: &str,
    allow_loopback: bool,
) -> Result<RelayCaps, Nip11Failure> {
    let url = document_url(endpoint, allow_loopback)?;
    fetch.caps(url, allow_loopback).await
}

fn cache_with(fetch: Nip11Fetch) -> RelayCapsCache {
    RelayCapsCache {
        slots: Arc::default(),
        fetch,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_the_caps_from_the_relays_own_url() {
    let server = DocumentServer::start(Reply::Document {
        status: 200,
        body: STRFRY_NIP11.to_owned(),
    })
    .await;

    let caps = fetch(&no_dns(), &server.relay("/nostr"), true)
        .await
        .unwrap();

    assert_eq!(
        caps,
        RelayCaps {
            max_limit: Some(500),
            negentropy: true,
        }
    );
    let heads = server.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    let head = heads[0].to_ascii_lowercase();
    assert!(head.starts_with("get /nostr http/1.1\r\n"), "{head}");
    assert!(
        head.contains("\r\naccept: application/nostr+json\r\n"),
        "{head}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_or_missing_document_reads_as_unknown_caps() {
    for (status, body, expected) in [
        (200, "not json".to_owned(), Err(Nip11Failure::Malformed)),
        (
            200,
            format!(r#"{{"description":"{}"}}"#, "x".repeat(MAX_DOCUMENT_BYTES)),
            Err(Nip11Failure::Malformed),
        ),
        // JSON without the fields, or with them mistyped, reads as unknown.
        (200, "[500]".to_owned(), Ok(RelayCaps::default())),
        (
            200,
            r#"{"limitation":{"max_limit":"500"},"supported_nips":"77"}"#.to_owned(),
            Ok(RelayCaps::default()),
        ),
        (404, STRFRY_NIP11.to_owned(), Err(Nip11Failure::Missing)),
        (301, String::new(), Err(Nip11Failure::Missing)),
    ] {
        let server = DocumentServer::start(Reply::Document { status, body }).await;
        let relay = server.relay("/");
        assert_eq!(fetch(&no_dns(), &relay, true).await, expected, "{status}");
        assert_eq!(
            cache_with(no_dns()).caps(&relay, true).await,
            RelayCaps::default()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_never_answers_times_out_to_unknown_caps() {
    let server = DocumentServer::start(Reply::Hang).await;
    let short = Nip11Fetch {
        request_timeout: Duration::from_millis(300),
        ..no_dns()
    };

    let started = std::time::Instant::now();
    let failure = fetch(&short, &server.relay("/"), true).await.unwrap_err();

    assert_eq!(failure, Nip11Failure::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(server.connections(), 1);
    assert_eq!(
        cache_with(short).caps(&server.relay("/"), true).await,
        RelayCaps::default()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_relays_and_addresses_are_never_dialed() {
    let server = DocumentServer::start(Reply::Document {
        status: 200,
        body: STRFRY_NIP11.to_owned(),
    })
    .await;
    let retired = format!("wss://{}", transport_nostr::retired_relay_hosts()[0]);

    // Refused before DNS: loopback without the dev flag, non-public literals,
    // retired hosts, public plaintext, and anything that is not a relay URL.
    for (endpoint, allow_loopback) in [
        (server.relay("/"), false),
        ("ws://localhost:7777".to_owned(), false),
        ("wss://10.1.2.3".to_owned(), true),
        ("wss://[fd00::1]".to_owned(), true),
        ("wss://169.254.169.254".to_owned(), true),
        (retired, true),
        ("ws://relay.example.com".to_owned(), true),
        ("https://relay.example.com".to_owned(), true),
        ("not a url".to_owned(), true),
    ] {
        assert_eq!(
            fetch(&no_dns(), &endpoint, allow_loopback).await,
            Err(Nip11Failure::Refused),
            "{endpoint}"
        );
    }

    // Refused after DNS: a public name with a private, link-local or loopback
    // address (the dev flag admits loopback only for a literal loopback
    // host), and `localhost` resolving anywhere but loopback.
    for (endpoint, ip) in [
        ("wss://relay.example.com", "10.0.0.7"),
        ("wss://relay.example.com", "169.254.169.254"),
        ("wss://relay.example.com", "127.0.0.1"),
        ("wss://relay.example.com", "::1"),
        ("ws://localhost:7777", "93.184.216.34"),
    ] {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let resolving = fetch_with(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            vec![ip.parse().unwrap()]
        });
        assert_eq!(
            fetch(&resolving, endpoint, true).await,
            Err(Nip11Failure::Refused),
            "{endpoint} -> {ip}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    // One unsafe address among public ones refuses the whole relay.
    let mixed = fetch_with(|_| {
        vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.7".parse().unwrap(),
        ]
    });
    assert_eq!(
        fetch(&mixed, "wss://relay.example.com", true).await,
        Err(Nip11Failure::Refused)
    );

    assert_eq!(server.connections(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caps_are_fetched_once_per_freshness_window() {
    let server = DocumentServer::start(Reply::Document {
        status: 200,
        body: STRFRY_NIP11.to_owned(),
    })
    .await;
    let cache = cache_with(no_dns());
    let relay = server.relay("/");

    let first = cache.caps(&relay, true).await;
    // Another spelling of the same relay shares its entry.
    let second = cache.caps(&server.relay("").to_uppercase(), true).await;
    assert_eq!(first.max_limit, Some(500));
    assert_eq!(second, first);
    assert_eq!(server.connections(), 1);

    // Past the window the document is fetched again.
    let key = document_url(&relay, true).unwrap();
    let slot = cache.slot(key.as_str());
    let fresh_until = slot.lock().await.as_ref().unwrap().fresh_until;
    assert!(fresh_until >= Instant::now() + DOCUMENT_FRESH_FOR - Duration::from_secs(60));
    slot.lock().await.as_mut().unwrap().fresh_until = Instant::now();
    assert_eq!(cache.caps(&relay, true).await, first);
    assert_eq!(server.connections(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_caps_are_retried_sooner_than_a_document_is_refreshed() {
    let server = DocumentServer::start(Reply::Document {
        status: 404,
        body: String::new(),
    })
    .await;
    let cache = cache_with(no_dns());
    let relay = server.relay("/");

    assert_eq!(cache.caps(&relay, true).await, RelayCaps::default());
    assert_eq!(cache.caps(&relay, true).await, RelayCaps::default());
    assert_eq!(server.connections(), 1);

    let key = document_url(&relay, true).unwrap();
    let fresh_until = cache
        .slot(key.as_str())
        .lock()
        .await
        .as_ref()
        .unwrap()
        .fresh_until;
    assert!(fresh_until <= Instant::now() + UNKNOWN_FRESH_FOR);
    assert!(UNKNOWN_FRESH_FOR < DOCUMENT_FRESH_FOR);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_callers_share_one_fetch() {
    let server = DocumentServer::start(Reply::Slow {
        delay: Duration::from_millis(200),
        body: STRFRY_NIP11.to_owned(),
    })
    .await;
    let cache = cache_with(no_dns());
    let relay = server.relay("/");

    let (left, right) = tokio::join!(cache.caps(&relay, true), cache.caps(&relay, true));

    assert_eq!(left.max_limit, Some(500));
    assert_eq!(left, right);
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_full_cache_drops_the_idle_entry_due_soonest() {
    let now = Instant::now();
    let mut slots = HashMap::new();
    for (key, fresh_for) in [("a", 30), ("b", 10), ("c", 20)] {
        slots.insert(
            key.to_owned(),
            Arc::new(tokio::sync::Mutex::new(Some(CachedCaps {
                caps: RelayCaps::default(),
                fresh_until: now + Duration::from_secs(fresh_for),
            }))),
        );
    }
    // A caller handed "b" but not yet locking it still holds it.
    let _about_to_lock = slots["b"].clone();

    assert!(evict_one(&mut slots));

    let mut left = slots.keys().cloned().collect::<Vec<_>>();
    left.sort();
    assert_eq!(left, ["a", "b"]);
}

#[test]
fn a_cache_overfilled_by_held_entries_shrinks_back_once_they_are_released() {
    let cache = cache_with(no_dns());
    let held = (0..MAX_CACHED_RELAYS + 3)
        .map(|relay| cache.slot(&format!("relay-{relay}")))
        .collect::<Vec<_>>();
    assert_eq!(cache.slots.lock().unwrap().len(), MAX_CACHED_RELAYS + 3);

    drop(held);
    let _next = cache.slot("relay-next");

    assert_eq!(cache.slots.lock().unwrap().len(), MAX_CACHED_RELAYS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_app_fetches_loopback_relays_only_under_the_dev_flag() {
    let server = DocumentServer::start(Reply::Document {
        status: 200,
        body: STRFRY_NIP11.to_owned(),
    })
    .await;
    let relay = server.relay("/");
    let (production_root, dev_root) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let production = crate::MarmotApp::with_relays_and_config(
        production_root.path(),
        vec![],
        crate::MarmotAppConfig::white_noise(),
    );
    let dev = crate::MarmotApp::with_relays_and_config(
        dev_root.path(),
        vec![],
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );

    assert_eq!(production.relay_caps(&relay).await, RelayCaps::default());
    assert_eq!(server.connections(), 0);
    assert_eq!(dev.relay_caps(&relay).await.max_limit, Some(500));
    assert_eq!(server.connections(), 1);
}
