use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use nostr::nips::nip01::Coordinate;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::image_inspect::test_images::{jpeg, png};

fn tag(values: &[&str]) -> Tag {
    Tag::parse(
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn signed(keys: &Keys, kind: u16, tags: Vec<Tag>) -> Event {
    EventBuilder::new(Kind::Custom(kind), "")
        .tags(tags)
        .finalize(keys)
        .unwrap()
}

fn emoji_tag(shortcode: &str, url: &str) -> Tag {
    tag(&["emoji", shortcode, url])
}

#[test]
fn valid_set_keeps_metadata_and_entries_in_order() {
    let keys = Keys::generate();
    let event = signed(
        &keys,
        EMOJI_SET_KIND,
        vec![
            tag(&["d", "blobs"]),
            tag(&["title", "Blob cats"]),
            tag(&["description", "Round\ncats"]),
            tag(&["image", "https://cdn.example/cover.png"]),
            emoji_tag("blob_cat", "https://cdn.example/a.png"),
            emoji_tag("Blob-2", "https://cdn.example/b.webp"),
            // NIP-30 allows a fourth value naming the set; it is ignored.
            tag(&["emoji", "three", "https://cdn.example/c.gif", "30030:x:y"]),
        ],
    );

    let set = stored_set_from_event(&event, false).unwrap();

    assert_eq!(
        set.coordinate,
        format!("30030:{}:blobs", keys.public_key().to_hex())
    );
    assert_eq!(set.title.as_deref(), Some("Blob cats"));
    assert_eq!(set.description.as_deref(), Some("Round\ncats"));
    assert_eq!(
        set.image_url.as_deref(),
        Some("https://cdn.example/cover.png")
    );
    assert_eq!(
        set.emoji
            .iter()
            .map(|entry| entry.shortcode.as_str())
            .collect::<Vec<_>>(),
        vec!["blob_cat", "Blob-2", "three"]
    );
    assert_eq!(set.skipped_count, 0);
}

#[test]
fn hostile_entries_are_dropped_and_reported_not_fatal() {
    let keys = Keys::generate();
    let long_url = format!("https://cdn.example/{}", "a".repeat(MAX_EMOJI_URL_BYTES));
    let refused_urls = [
        "http://cdn.example/a.png",
        "https://127.0.0.1/a.png",
        "https://10.0.0.1/a.png",
        "https://169.254.1.1/a.png",
        "https://0.0.0.0/a.png",
        "https://[::1]/a.png",
        "https://[::ffff:127.0.0.1]/a.png",
        "https://[::ffff:10.0.0.1]/a.png",
        "https://localhost/a.png",
        "https://user:secret@cdn.example/a.png",
        "https://cdn.example/a.png#frag",
        " https://cdn.example/a.png",
        "javascript:alert(1)",
        long_url.as_str(),
    ];
    let mut tags = vec![
        tag(&["d", "hostile"]),
        tag(&["title", &"t".repeat(MAX_TITLE_BYTES + 1)]),
        tag(&["image", "https://192.168.1.1/cover.png"]),
        emoji_tag("ok", "https://cdn.example/ok.png"),
        emoji_tag("", "https://cdn.example/a.png"),
        emoji_tag(
            &"x".repeat(MAX_CUSTOM_EMOJI_SHORTCODE_BYTES + 1),
            "https://cdn.example/a.png",
        ),
        emoji_tag("has space", "https://cdn.example/a.png"),
        emoji_tag("colon:", "https://cdn.example/a.png"),
        emoji_tag("émoji", "https://cdn.example/a.png"),
        tag(&["emoji", "no_url"]),
        emoji_tag("ok", "https://cdn.example/again.png"),
    ];
    tags.extend(
        refused_urls
            .iter()
            .enumerate()
            .map(|(index, url)| emoji_tag(&format!("u{index}"), url)),
    );
    let event = signed(&keys, EMOJI_SET_KIND, tags);

    let set = stored_set_from_event(&event, false).unwrap();

    assert_eq!(set.title, None);
    assert_eq!(set.image_url, None);
    assert_eq!(set.emoji.len(), 1);
    let reasons = set
        .skipped
        .iter()
        .map(|skip| (skip.position, skip.shortcode.clone(), skip.reason.clone()))
        .collect::<Vec<_>>();
    let mut expected = vec![
        (1, None, "invalid_shortcode".to_owned()),
        (2, None, "invalid_shortcode".to_owned()),
        (3, None, "invalid_shortcode".to_owned()),
        (4, None, "invalid_shortcode".to_owned()),
        (5, None, "invalid_shortcode".to_owned()),
        (6, Some("no_url".to_owned()), "invalid_url".to_owned()),
        (7, Some("ok".to_owned()), "duplicate".to_owned()),
    ];
    expected.extend((0..refused_urls.len()).map(|index| {
        (
            8 + index as u32,
            Some(format!("u{index}")),
            "invalid_url".to_owned(),
        )
    }));
    assert_eq!(reasons, expected);
    assert_eq!(set.skipped_count as usize, expected.len());
}

#[test]
fn oversize_sets_cap_entries_and_skip_records() {
    let keys = Keys::generate();
    let mut tags = vec![tag(&["d", "big"])];
    tags.extend(
        (0..MAX_EMOJI_PER_SET + 100)
            .map(|index| emoji_tag(&format!("e{index}"), "https://cdn.example/e.png")),
    );
    let set = stored_set_from_event(&signed(&keys, EMOJI_SET_KIND, tags), false).unwrap();

    assert_eq!(set.emoji.len(), MAX_EMOJI_PER_SET);
    assert_eq!(set.skipped_count, 100);
    assert_eq!(set.skipped.len(), MAX_RECORDED_SKIPS);
    assert!(set.skipped.iter().all(|skip| skip.reason == "over_cap"));
    assert_eq!(set.skipped[0].position, MAX_EMOJI_PER_SET as u32);
}

#[test]
fn bad_envelopes_are_refused_and_empty_sets_parse_empty() {
    let keys = Keys::generate();
    // Kept so it can supersede older versions; listings hide it.
    let empty = signed(
        &keys,
        EMOJI_SET_KIND,
        vec![
            tag(&["d", "x"]),
            emoji_tag("bad code", "https://cdn.example/a.png"),
        ],
    );
    let parsed = stored_set_from_event(&empty, false).unwrap();
    assert!(parsed.emoji.is_empty());
    assert_eq!(parsed.skipped_count, 1);

    let future = EventBuilder::new(Kind::Custom(EMOJI_SET_KIND), "")
        .tags([
            tag(&["d", "x"]),
            emoji_tag("ok", "https://cdn.example/a.png"),
        ])
        .custom_created_at(Timestamp::from_secs(
            unix_now_seconds() + MAX_FUTURE_EVENT_SKEW_SECONDS + 60,
        ))
        .finalize(&keys)
        .unwrap();
    assert!(stored_set_from_event(&future, false).is_err());

    let wrong_kind = signed(
        &keys,
        30031,
        vec![emoji_tag("ok", "https://cdn.example/a.png")],
    );
    assert!(stored_set_from_event(&wrong_kind, false).is_err());

    let mut forged = signed(
        &keys,
        EMOJI_SET_KIND,
        vec![
            tag(&["d", "x"]),
            emoji_tag("ok", "https://cdn.example/a.png"),
        ],
    );
    forged.content = "tampered".to_owned();
    assert!(stored_set_from_event(&forged, false).is_err());

    // A user list is read as the set of its loose emoji, whatever `d` says.
    let list = signed(
        &keys,
        USER_EMOJI_LIST_KIND,
        vec![
            tag(&["d", "ignored"]),
            emoji_tag("mine", "https://cdn.example/m.png"),
            tag(&["a", &format!("30030:{}:x", keys.public_key().to_hex())]),
        ],
    );
    let own = stored_set_from_event(&list, false).unwrap();
    assert_eq!(
        own.coordinate,
        format!("10030:{}:", keys.public_key().to_hex())
    );
    assert_eq!(own.identifier, "");
}

#[test]
fn set_input_accepts_coordinates_and_naddr_with_bounded_hints() {
    let keys = Keys::generate();
    let hex = keys.public_key().to_hex();
    let coordinate = format!("30030:{hex}:blobs");
    assert_eq!(parse_emoji_set_input(&coordinate).unwrap(), coordinate);
    assert_eq!(
        parse_emoji_set_input(&format!("30030:{}:blobs", hex.to_uppercase())).unwrap(),
        coordinate
    );
    assert_eq!(
        parse_emoji_set_input(&format!("10030:{hex}:")).unwrap(),
        format!("10030:{hex}:")
    );
    assert!(parse_emoji_set_input(&format!("10030:{hex}:named")).is_err());
    assert!(parse_emoji_set_input(&format!("30031:{hex}:blobs")).is_err());
    assert!(parse_emoji_set_input("30030:nothex:blobs").is_err());
    assert!(parse_emoji_set_input(&format!("30030:{hex}:{}", "d".repeat(257))).is_err());
    assert!(parse_emoji_set_input("").is_err());

    let relays = (0..12)
        .map(|index| RelayUrl::parse(&format!("wss://relay{}.example", index % 10)).unwrap())
        .collect::<Vec<_>>();
    let naddr = Nip19Coordinate::new(
        Coordinate::new(Kind::Custom(EMOJI_SET_KIND), keys.public_key()).identifier("blobs"),
        relays,
    )
    .to_bech32()
    .unwrap();
    let parsed = parse_input_with_relays(&format!("nostr:{naddr}")).unwrap();
    assert_eq!(parsed.address.coordinate(), coordinate);
    assert_eq!(parsed.relay_hints.len(), MAX_EMOJI_SET_RELAY_HINTS);
    assert_eq!(parsed.relay_hints[0].0, "wss://relay0.example");

    let sticker_naddr = Nip19Coordinate::new(
        Coordinate::new(Kind::Custom(30031), keys.public_key()).identifier("blobs"),
        Vec::<RelayUrl>::new(),
    )
    .to_bech32()
    .unwrap();
    assert!(parse_emoji_set_input(&sticker_naddr).is_err());
}

#[test]
fn image_validation_enforces_limits_and_stated_mime() {
    let still = png(64, 32, None);
    let image = validate_emoji_image(still.clone(), Some("image/png")).unwrap();
    assert_eq!(
        (image.mime, image.width, image.height, image.frames),
        ("image/png", 64, 32, 1)
    );
    assert_eq!(image.sha256, hex::encode(Sha256::digest(&still)));
    // No statement, a generic binary one, or any image type leaves magic
    // bytes to decide; the format comes from the bytes, never the server.
    assert!(validate_emoji_image(still.clone(), None).is_ok());
    assert!(validate_emoji_image(still.clone(), Some("application/octet-stream")).is_ok());
    let mislabeled = validate_emoji_image(still.clone(), Some("image/jpeg")).unwrap();
    assert_eq!(mislabeled.mime, "image/png");
    assert_eq!(
        validate_emoji_image(still.clone(), Some("image/gif"))
            .unwrap()
            .mime,
        "image/png"
    );
    // A stated non-image type is refused even when the bytes parse.
    for stated in ["text/html", "text/plain", "application/json", "image/"] {
        assert_eq!(
            validate_emoji_image(still.clone(), Some(stated)),
            Err(AppEmojiSkipReason::MimeMismatch),
            "{stated}"
        );
    }
    // An image type over bytes that are no image is still unsupported.
    assert_eq!(
        validate_emoji_image(b"<svg/>".to_vec(), Some("image/svg+xml")),
        Err(AppEmojiSkipReason::UnsupportedImage)
    );
    assert_eq!(
        validate_emoji_image(png(16, 16, Some(2)), Some("image/png"))
            .unwrap()
            .mime,
        "image/apng"
    );
    assert_eq!(
        validate_emoji_image(jpeg(20, 10), Some("image/jpeg"))
            .unwrap()
            .mime,
        "image/jpeg"
    );
    assert_eq!(
        validate_emoji_image(png(4097, 16, None), None),
        Err(AppEmojiSkipReason::TooLarge)
    );
    assert_eq!(
        validate_emoji_image(png(16, 16, Some(201)), None),
        Err(AppEmojiSkipReason::TooLarge)
    );
    let mut oversize = png(16, 16, None);
    oversize.resize(MAX_EMOJI_IMAGE_BYTES as usize + 1, 0);
    assert_eq!(
        validate_emoji_image(oversize, None),
        Err(AppEmojiSkipReason::TooLarge)
    );
    assert_eq!(
        validate_emoji_image(b"<svg/>".to_vec(), None),
        Err(AppEmojiSkipReason::UnsupportedImage)
    );
    assert_eq!(
        validate_emoji_image(Vec::new(), None),
        Err(AppEmojiSkipReason::UnsupportedImage)
    );
}

#[test]
fn shortcode_rule_is_the_chat_custom_emoji_rule() {
    for valid in ["a", "Blob_cat-2", &"x".repeat(64)] {
        assert!(is_custom_emoji_shortcode(valid), "{valid}");
    }
    for invalid in ["", &"x".repeat(65), "a b", "a:b", "émoji", "a.b", "🙂"] {
        assert!(!is_custom_emoji_shortcode(invalid), "{invalid}");
    }
}

#[test]
fn nothing_installed_names_the_shared_cause() {
    let skip = |reason| AppEmojiSkip {
        position: None,
        shortcode: Some("x".to_owned()),
        reason,
    };
    assert!(matches!(
        nothing_installed_error(&[skip(AppEmojiSkipReason::DownloadFailed)]),
        AppError::EmojiSetNetwork(_)
    ));
    assert!(matches!(
        nothing_installed_error(&[skip(AppEmojiSkipReason::OverCap)]),
        AppError::EmojiSetLimit(_)
    ));
    assert!(matches!(
        nothing_installed_error(&[skip(AppEmojiSkipReason::TooLarge)]),
        AppError::EmojiImageTooLarge(_)
    ));
    assert!(matches!(
        nothing_installed_error(&[skip(AppEmojiSkipReason::UnsupportedImage)]),
        AppError::EmojiImageUnsupported(_)
    ));
    assert!(matches!(
        nothing_installed_error(&[
            skip(AppEmojiSkipReason::UnsupportedImage),
            skip(AppEmojiSkipReason::MimeMismatch)
        ]),
        AppError::EmojiImageUnsupported(_)
    ));
    assert!(matches!(
        nothing_installed_error(&[
            skip(AppEmojiSkipReason::TooLarge),
            skip(AppEmojiSkipReason::MimeMismatch)
        ]),
        AppError::InvalidEmojiSet(_)
    ));
}

/// A newer version with no valid emoji replaces a populated one, so the old
/// version's entries can no longer be listed or installed.
#[test]
fn an_emptied_version_supersedes_the_populated_one() {
    let storage = storage_sqlite::SqliteAccountStorage::in_memory()
        .unwrap()
        .app_storage();
    let keys = Keys::generate();
    let at = |secs, tags| {
        EventBuilder::new(Kind::Custom(EMOJI_SET_KIND), "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(secs))
            .finalize(&keys)
            .unwrap()
    };
    let populated = at(
        1_000,
        vec![
            tag(&["d", "x"]),
            emoji_tag("ok", "https://cdn.example/a.png"),
        ],
    );
    let emptied = at(
        2_000,
        vec![
            tag(&["d", "x"]),
            emoji_tag("bad code", "https://cdn.example/a.png"),
        ],
    );
    assert_eq!(
        ingest_discovered_sets(&storage, vec![populated.clone()], false).unwrap(),
        (1, 1)
    );
    assert_eq!(
        ingest_discovered_sets(&storage, vec![populated, emptied], false).unwrap(),
        (0, 1)
    );
    let coordinate = format!("30030:{}:x", keys.public_key().to_hex());
    assert!(
        storage
            .emoji_set(&coordinate)
            .unwrap()
            .unwrap()
            .emoji
            .is_empty()
    );
    assert!(storage.emoji_sets(false, None, 10).unwrap().is_empty());
}

/// One canned HTTP response. `content_length: false` streams the body until
/// the connection closes.
#[derive(Clone)]
struct Canned {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    content_length: bool,
    /// Never answer: hold the connection until the client drops it.
    stall: bool,
}

impl Canned {
    fn image(content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status: "200 OK",
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body,
            content_length: true,
            stall: false,
        }
    }

    fn stalled() -> Self {
        Self {
            stall: true,
            ..Self::image("image/png", Vec::new())
        }
    }
}

/// A loopback HTTP/1.1 server that answers each path from a mutable table
/// and counts every request it receives, and every stalled request whose
/// client hung up.
struct ImageHost {
    base: String,
    requests: Arc<AtomicUsize>,
    stalled_open: Arc<AtomicUsize>,
    stalled_dropped: Arc<AtomicUsize>,
    routes: Arc<Mutex<HashMap<String, Canned>>>,
}

impl ImageHost {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let stalled_open = Arc::new(AtomicUsize::new(0));
        let stalled_dropped = Arc::new(AtomicUsize::new(0));
        let routes = Arc::new(Mutex::new(HashMap::<String, Canned>::new()));
        let (counter, table) = (requests.clone(), routes.clone());
        let (open, dropped) = (stalled_open.clone(), stalled_dropped.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let table = table.clone();
                let (open, dropped) = (open.clone(), dropped.clone());
                tokio::spawn(async move {
                    let mut buffer = vec![0; 8192];
                    let mut read = 0;
                    while !buffer[..read]
                        .windows(4)
                        .any(|window| window == b"\r\n\r\n")
                    {
                        match stream.read(&mut buffer[read..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(count) => read += count,
                        }
                    }
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let canned = table.lock().unwrap().get(&path).cloned();
                    let canned = canned.unwrap_or(Canned {
                        status: "404 Not Found",
                        headers: Vec::new(),
                        body: Vec::new(),
                        content_length: true,
                        stall: false,
                    });
                    if canned.stall {
                        open.fetch_add(1, Ordering::SeqCst);
                        // Wait for the client to hang up.
                        let mut byte = [0; 1];
                        while !matches!(stream.read(&mut byte).await, Ok(0) | Err(_)) {}
                        dropped.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    let mut head = format!("HTTP/1.1 {}\r\nConnection: close\r\n", canned.status);
                    for (name, value) in &canned.headers {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    if canned.content_length {
                        head.push_str(&format!("Content-Length: {}\r\n", canned.body.len()));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&canned.body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            base,
            requests,
            stalled_open,
            stalled_dropped,
            routes,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn serve(&self, path: &str, canned: Canned) {
        self.routes.lock().unwrap().insert(path.to_owned(), canned);
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    _relay: nostr_relay_builder::LocalRelay,
    relay_database: nostr_relay_builder::prelude::MemoryDatabase,
    app: MarmotApp,
    account_id: String,
    host: ImageHost,
    author: Keys,
    set_created_at: u64,
    set_coordinate: String,
    set_naddr: String,
}

impl Fixture {
    fn account(&self) -> &str {
        &self.account_id
    }

    /// The event id of the stored version of the fixture set, as a host
    /// showing it would read it.
    async fn shown_event_id(&self) -> String {
        self.app
            .emoji_set(self.account(), &self.set_coordinate)
            .await
            .unwrap()
            .unwrap()
            .event_id_hex
    }

    /// Put an event on the fixture relay, as its author publishing it would.
    async fn publish(&self, event: &Event) {
        use nostr_relay_builder::prelude::NostrDatabase;
        self.relay_database
            .save_event(&serde_json::from_str(&event.as_json()).unwrap())
            .await
            .unwrap();
    }

    /// A newer version of the fixture set with `entries` as its emoji.
    fn next_version(&self, after: u64, entries: &[(&str, &str)]) -> Event {
        self.next_version_with(after, entries, [])
    }

    fn next_version_with(
        &self,
        after: u64,
        entries: &[(&str, &str)],
        extra: impl IntoIterator<Item = Tag>,
    ) -> Event {
        let mut tags = vec![tag(&["d", "blobs"]), tag(&["title", "Blob cats"])];
        tags.extend(extra);
        tags.extend(
            entries
                .iter()
                .map(|(shortcode, path)| emoji_tag(shortcode, &self.host.url(path))),
        );
        EventBuilder::new(Kind::Custom(EMOJI_SET_KIND), "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(after + 1))
            .finalize(&self.author)
            .unwrap()
    }

    async fn assert_nothing_installed(&self) {
        assert!(
            self.app
                .installed_custom_emoji(self.account())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            self.app
                .emoji_sets(self.account(), true, None, None)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

async fn fixture() -> Fixture {
    use nostr_relay_builder::prelude::{
        MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RelayBuilder,
    };

    let host = ImageHost::start().await;
    let still = png(32, 32, None);
    host.serve("/good.png", Canned::image("image/png", still.clone()));
    host.serve("/lied.png", Canned::image("text/html", still.clone()));
    host.serve("/mislabeled.png", Canned::image("image/gif", still.clone()));
    host.serve(
        "/animated.png",
        Canned::image("image/png", png(16, 16, Some(201))),
    );
    host.serve(
        "/huge-declared.png",
        Canned::image("image/png", vec![0; MAX_EMOJI_IMAGE_BYTES as usize + 1]),
    );
    host.serve(
        "/huge-streamed.png",
        Canned {
            content_length: false,
            ..Canned::image("image/png", vec![0; MAX_EMOJI_IMAGE_BYTES as usize + 1])
        },
    );
    // A redirect that leaves the loopback host for a private address.
    host.serve(
        "/redirect.png",
        Canned {
            status: "302 Found",
            headers: vec![("Location".to_owned(), "http://10.0.0.1/x.png".to_owned())],
            body: Vec::new(),
            content_length: true,
            stall: false,
        },
    );
    host.serve("/mine.jpg", Canned::image("image/jpeg", jpeg(24, 24)));

    let author = Keys::generate();
    let user = Keys::generate();
    let set = signed(
        &author,
        EMOJI_SET_KIND,
        vec![
            tag(&["d", "blobs"]),
            tag(&["title", "Blob cats"]),
            emoji_tag("good", &host.url("/good.png")),
            emoji_tag("bad shortcode", &host.url("/good.png")),
            emoji_tag("lied", &host.url("/lied.png")),
            emoji_tag("mislabeled", &host.url("/mislabeled.png")),
            emoji_tag("animated", &host.url("/animated.png")),
            emoji_tag("declared", &host.url("/huge-declared.png")),
            emoji_tag("streamed", &host.url("/huge-streamed.png")),
            emoji_tag("redirect", &host.url("/redirect.png")),
            emoji_tag("missing", &host.url("/missing.png")),
        ],
    );
    let hidden = signed(
        &author,
        EMOJI_SET_KIND,
        vec![
            tag(&["d", "hidden"]),
            tag(&["title", "Nothing valid"]),
            emoji_tag("ok", "https://10.0.0.1/a.png"),
        ],
    );
    let set_coordinate = format!("30030:{}:blobs", author.public_key().to_hex());
    let list = signed(
        &user,
        USER_EMOJI_LIST_KIND,
        vec![
            emoji_tag("good", &host.url("/mine.jpg")),
            tag(&["a", &set_coordinate]),
            tag(&["a", &format!("30030:{}:gone", author.public_key().to_hex())]),
            tag(&["a", "not a coordinate"]),
        ],
    );
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    for event in [&set, &hidden, &list] {
        database
            .save_event(&serde_json::from_str(&event.as_json()).unwrap())
            .await
            .unwrap();
    }
    let relay_database = database.clone();
    let relay = nostr_relay_builder::LocalRelay::new(RelayBuilder::default().database(database));
    relay.run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let set_naddr = Nip19Coordinate::new(
        Coordinate::new(Kind::Custom(EMOJI_SET_KIND), author.public_key()).identifier("blobs"),
        [RelayUrl::parse(&relay_url).unwrap()],
    )
    .to_bech32()
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let home = crate::AccountHome::open(directory.path());
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let app = MarmotApp::with_relays_and_account_home_and_config(
        directory.path(),
        vec![relay_url],
        home,
        crate::MarmotAppConfig::default()
            .with_allow_loopback_relay_endpoints(true)
            .with_allow_loopback_blob_endpoints(true),
    );
    Fixture {
        _directory: directory,
        _relay: relay,
        relay_database,
        app,
        account_id: account.account_id_hex,
        host,
        set_created_at: set.created_at.as_secs(),
        author,
        set_coordinate,
        set_naddr,
    }
}

/// The whole host flow against a local relay and image server: discovery,
/// the user's list and `naddr` fetch never fetch an image; a preview fetches
/// one; install fetches each emoji once, reports every skipped entry and
/// pins the bytes; reads are local; uninstall removes the bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn emoji_sets_round_trip_against_a_local_relay_and_image_host() {
    let fixture = fixture().await;
    let (app, account, host) = (&fixture.app, fixture.account_id.as_str(), &fixture.host);

    // Text-only discovery.
    let synced = app.sync_emoji_sets(account, None).await.unwrap();
    // The set with no valid emoji is stored, so it can supersede, but hidden.
    assert_eq!((synced.discovered, synced.updated), (1, 2));
    let listed = app
        .emoji_sets(account, false, Some("BLOB"), None)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1, "the set with no valid emoji stays hidden");
    let set = &listed[0];
    assert_eq!(set.coordinate, fixture.set_coordinate);
    assert_eq!(set.title.as_deref(), Some("Blob cats"));
    assert_eq!(set.emoji.len(), 8);
    assert_eq!(
        set.skipped,
        vec![AppEmojiSkip {
            position: Some(1),
            shortcode: None,
            reason: AppEmojiSkipReason::InvalidShortcode,
        }]
    );
    assert!(set.installed.is_none());
    assert_eq!(
        app.emoji_sets(account, false, Some("streamed"), None)
            .await
            .unwrap()
            .len(),
        1,
        "search matches shortcodes"
    );

    let list = app.user_emoji_list(account).await.unwrap();
    let own = list.own_emoji.unwrap();
    assert_eq!(own.coordinate, format!("10030:{account}:"));
    assert_eq!(own.emoji.len(), 1);
    assert_eq!(
        list.sets
            .iter()
            .map(|set| set.coordinate.as_str())
            .collect::<Vec<_>>(),
        vec![fixture.set_coordinate.as_str()]
    );
    assert_eq!(list.missing_set_coordinates.len(), 1);
    assert!(list.missing_set_coordinates[0].ends_with(":gone"));

    let fetched = app
        .fetch_emoji_set(account, &fixture.set_naddr)
        .await
        .unwrap();
    assert_eq!(fetched.coordinate, fixture.set_coordinate);
    assert_eq!(host.requests(), 0, "sync and set reads never fetch images");

    // An explicit preview fetches exactly one image.
    let shown = set.event_id_hex.as_str();
    let preview = app
        .fetch_emoji_set_asset(account, &fixture.set_coordinate, shown, "good")
        .await
        .unwrap();
    assert_eq!(preview.bytes, png(32, 32, None));
    assert_eq!(host.requests(), 1);
    assert!(matches!(
        app.fetch_emoji_set_asset(account, &fixture.set_coordinate, shown, "lied")
            .await,
        Err(AppError::EmojiImageUnsupported(_))
    ));
    assert!(matches!(
        app.fetch_emoji_set_asset(account, &fixture.set_coordinate, shown, "declared")
            .await,
        Err(AppError::EmojiImageTooLarge(_))
    ));
    assert!(matches!(
        app.fetch_emoji_set_asset(account, &fixture.set_coordinate, shown, "unknown")
            .await,
        Err(AppError::EmojiSetNotFound)
    ));
    // The set has no cover: nothing to fetch.
    let requests = host.requests();
    assert!(matches!(
        app.fetch_emoji_set_cover(account, &fixture.set_coordinate, shown)
            .await,
        Err(AppError::EmojiSetNotFound)
    ));
    assert_eq!(host.requests(), requests);

    // Install downloads each entry once and reports every skip.
    let before_install = host.requests();
    let control = EmojiSetInstallControl::new();
    let installed = app
        .install_emoji_set(account, &fixture.set_coordinate, shown, &control)
        .await
        .unwrap();
    assert_eq!(
        installed.installed_count, 2,
        "a mislabeled image type installs"
    );
    let skipped = installed
        .skipped
        .iter()
        .map(|skip| (skip.shortcode.clone(), skip.reason))
        .collect::<Vec<_>>();
    assert_eq!(
        skipped,
        vec![
            (None, AppEmojiSkipReason::InvalidShortcode),
            (Some("lied".to_owned()), AppEmojiSkipReason::MimeMismatch),
            (Some("animated".to_owned()), AppEmojiSkipReason::TooLarge),
            (Some("declared".to_owned()), AppEmojiSkipReason::TooLarge),
            (Some("streamed".to_owned()), AppEmojiSkipReason::TooLarge),
            (
                Some("redirect".to_owned()),
                AppEmojiSkipReason::DownloadFailed
            ),
            (
                Some("missing".to_owned()),
                AppEmojiSkipReason::DownloadFailed
            ),
        ]
    );
    assert_eq!(host.requests() - before_install, 8);
    let progress = control.progress();
    assert_eq!((progress.completed_emoji, progress.total_emoji), (8, 8));
    assert!(progress.transferred_bytes >= 2 * png(32, 32, None).len() as u64);
    let state = installed.set.installed.clone().unwrap();
    assert_eq!(state.event_id_hex, installed.set.event_id_hex);
    assert!(!state.update_available);

    // The installed bytes are pinned: a changed image on the host does not
    // reach them, and reading them is local.
    host.serve("/good.png", Canned::image("image/png", png(48, 48, None)));
    let requests = host.requests();
    let picker = app.installed_custom_emoji(account).await.unwrap();
    assert_eq!(
        picker
            .iter()
            .map(|emoji| (emoji.shortcode.as_str(), emoji.mime.as_str()))
            .collect::<Vec<_>>(),
        vec![("good", "image/png"), ("mislabeled", "image/png")]
    );
    assert_eq!(picker[0].set_title.as_deref(), Some("Blob cats"));
    assert_eq!((picker[0].width, picker[0].height), (32, 32));
    assert!(!picker[0].shortcode_collision);
    let read = app
        .read_installed_custom_emoji(account, &fixture.set_coordinate, "good")
        .await
        .unwrap();
    assert_eq!(read.bytes, png(32, 32, None));
    assert_eq!(read.emoji.sha256, hex::encode(Sha256::digest(&read.bytes)));
    assert_eq!(host.requests(), requests);

    // The user's own list installs as a set; the shared shortcode is
    // reported on both, not resolved.
    app.install_emoji_set(
        account,
        &own.coordinate,
        &own.event_id_hex,
        &EmojiSetInstallControl::new(),
    )
    .await
    .unwrap();
    let picker = app.installed_custom_emoji(account).await.unwrap();
    assert_eq!(
        picker
            .iter()
            .map(|emoji| (
                emoji.set_coordinate.as_str(),
                emoji.shortcode.as_str(),
                emoji.shortcode_collision
            ))
            .collect::<Vec<_>>(),
        vec![
            (fixture.set_coordinate.as_str(), "good", true),
            (fixture.set_coordinate.as_str(), "mislabeled", false),
            (own.coordinate.as_str(), "good", true),
        ]
    );
    assert_eq!(
        app.emoji_sets(account, true, None, None)
            .await
            .unwrap()
            .len(),
        2
    );

    // A newer version with no valid emoji supersedes the installed one: it is
    // hidden from discovery and cannot be fetched or installed, while the
    // pinned bytes stay until the user uninstalls.
    let emptied = EventBuilder::new(Kind::Custom(EMOJI_SET_KIND), "")
        .tags([
            tag(&["d", "blobs"]),
            emoji_tag("bad code", &host.url("/good.png")),
        ])
        .custom_created_at(Timestamp::from_secs(fixture.set_created_at + 1))
        .finalize(&fixture.author)
        .unwrap();
    ingest_discovered_sets(
        &app.emoji_storage(account).unwrap(),
        vec![emptied.clone()],
        true,
    )
    .unwrap();
    assert!(
        app.emoji_sets(account, false, Some("BLOB"), None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        app.emoji_sets(account, true, None, None).await.unwrap()[0]
            .installed
            .as_ref()
            .unwrap()
            .update_available
    );
    assert!(matches!(
        app.fetch_emoji_set(account, &fixture.set_naddr).await,
        Err(AppError::InvalidEmojiSet(_))
    ));
    let requests = host.requests();
    assert!(matches!(
        app.install_emoji_set(
            account,
            &fixture.set_coordinate,
            &emptied.id.to_hex(),
            &EmojiSetInstallControl::new(),
        )
        .await,
        Err(AppError::InvalidEmojiSet(_))
    ));
    assert_eq!(host.requests(), requests);
    assert!(
        app.read_installed_custom_emoji(account, &fixture.set_coordinate, "good")
            .await
            .is_ok()
    );

    // Uninstall removes the stored bytes.
    assert!(
        app.uninstall_emoji_set(account, &fixture.set_coordinate)
            .await
            .unwrap()
    );
    assert!(matches!(
        app.read_installed_custom_emoji(account, &fixture.set_coordinate, "good")
            .await,
        Err(AppError::EmojiSetNotFound)
    ));
    let picker = app.installed_custom_emoji(account).await.unwrap();
    assert_eq!(picker.len(), 1);
    assert!(!picker[0].shortcode_collision);
    assert!(
        !app.uninstall_emoji_set(account, &fixture.set_coordinate)
            .await
            .unwrap()
    );
}

/// A set whose every entry fails to download is refused with a network
/// error and installs nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_with_no_usable_emoji_installs_nothing() {
    let fixture = fixture().await;
    let (app, account) = (&fixture.app, fixture.account_id.as_str());
    app.sync_emoji_sets(account, None).await.unwrap();
    let shown = fixture.shown_event_id().await;
    fixture.host.routes.lock().unwrap().clear();

    let result = app
        .install_emoji_set(
            account,
            &fixture.set_coordinate,
            &shown,
            &EmojiSetInstallControl::new(),
        )
        .await;

    assert!(
        matches!(result, Err(AppError::EmojiSetNetwork(_))),
        "{result:?}"
    );
    fixture.assert_nothing_installed().await;
}

/// An image that does not fit the remaining byte budget is skipped on its
/// own; a later, smaller one is still fetched and kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_image_over_the_budget_does_not_stop_later_ones() {
    let fixture = fixture().await;
    // One byte over the budget, and under the twice-the-budget stop.
    let big = png(32, 32, Some(2));
    let budget = big.len() as u64 - 1;
    assert!((png(32, 32, None).len() as u64) <= budget);
    fixture
        .host
        .serve("/big.png", Canned::image("image/png", big));
    let entries = vec![
        StoredEmojiSetEntry {
            shortcode: "big".to_owned(),
            url: fixture.host.url("/big.png"),
        },
        StoredEmojiSetEntry {
            shortcode: "good".to_owned(),
            url: fixture.host.url("/good.png"),
        },
    ];

    let (kept, skipped) = fixture
        .app
        .download_set(&entries, budget, &EmojiSetInstallControl::new())
        .await;

    assert_eq!(
        kept.iter()
            .map(|(emoji, _)| emoji.shortcode.as_str())
            .collect::<Vec<_>>(),
        vec!["good"]
    );
    assert_eq!(
        skipped
            .iter()
            .map(|skip| (skip.shortcode.as_deref(), skip.reason))
            .collect::<Vec<_>>(),
        vec![(Some("big"), AppEmojiSkipReason::OverCap)]
    );
}

/// No download dials once the install is cancelled, even one the stream
/// starts before the install's `select!` looks at the control again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_install_starts_no_download() {
    let fixture = fixture().await;
    let entries = (0..3)
        .map(|index| StoredEmojiSetEntry {
            shortcode: format!("good{index}"),
            url: fixture.host.url("/good.png"),
        })
        .collect::<Vec<_>>();
    let control = EmojiSetInstallControl::new();
    control.cancel();

    let (kept, _) = fixture
        .app
        .download_set(&entries, MAX_INSTALLED_EMOJI_SET_BYTES, &control)
        .await;

    assert!(kept.is_empty());
    assert_eq!(fixture.host.requests(), 0);
}

/// Bodies rejected after download still count toward the download stop, so
/// a set of bad images cannot be pulled without bound; later entries are
/// skipped without being fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_bodies_count_toward_the_download_stop() {
    let fixture = fixture().await;
    let mut entries = (0..10)
        .map(|index| StoredEmojiSetEntry {
            shortcode: format!("lied{index}"),
            url: fixture.host.url("/lied.png"),
        })
        .collect::<Vec<_>>();
    entries.push(StoredEmojiSetEntry {
        shortcode: "good".to_owned(),
        url: fixture.host.url("/good.png"),
    });
    // Two rejected bodies reach twice this budget.
    let budget = png(32, 32, None).len() as u64;

    let control = EmojiSetInstallControl::new();
    control.start(entries.len());
    let (kept, skipped) = fixture.app.download_set(&entries, budget, &control).await;

    assert!(kept.is_empty());
    assert!(
        fixture.host.requests() <= 2 + EMOJI_DOWNLOAD_CONCURRENCY,
        "{} requests",
        fixture.host.requests()
    );
    let last = skipped.last().unwrap();
    assert_eq!(
        (last.shortcode.as_deref(), last.reason),
        (Some("good"), AppEmojiSkipReason::OverCap)
    );
    assert_eq!(skipped.len(), entries.len());
    // Entries given up on still count, so a progress bar reaches its end.
    let progress = control.progress();
    assert_eq!(progress.completed_emoji, progress.total_emoji);
}

/// Cancelling an install while its storage write runs must not free the
/// account's emoji mutation lock: an uninstall that took it then could be
/// undone by the write landing afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_install_write_keeps_the_mutation_lock_until_it_lands() {
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let guard = lock.clone().lock_owned().await;
    let caller = tokio::spawn(write_holding_guard(guard, move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    }));
    tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
        .await
        .unwrap();

    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());

    assert!(
        lock.try_lock().is_err(),
        "a mutation could run before the cancelled write lands"
    );
    release_tx.send(()).unwrap();
    // Free again once the write has finished.
    drop(lock.lock().await);
}

/// Wait, bounded, until `ready` holds.
async fn wait_until(what: &str, ready: impl Fn() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !ready() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// Install, preview and cover downloads are bound to the version the user
/// was shown: a sync that stores a newer version between the read and the
/// tap makes them fail before any image request, and passing the current
/// version's id installs it. With nothing stored, install does not fetch
/// the set itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloads_refuse_a_version_the_user_was_not_shown() {
    let fixture = fixture().await;
    let (app, account, host) = (&fixture.app, fixture.account(), &fixture.host);
    let control = EmojiSetInstallControl::new();
    assert!(matches!(
        app.install_emoji_set(account, &fixture.set_coordinate, &"0".repeat(64), &control)
            .await,
        Err(AppError::EmojiSetNotFound)
    ));
    app.sync_emoji_sets(account, None).await.unwrap();
    let shown = fixture.shown_event_id().await;

    // The author moves the set to another image host, and a sync lands
    // before the user taps Install.
    let newer = fixture.next_version(fixture.set_created_at, &[("good", "/elsewhere.png")]);
    fixture.publish(&newer).await;
    app.sync_emoji_sets(account, None).await.unwrap();

    let current = newer.id.to_hex();
    let changed = |result: Result<_, AppError>| {
        matches!(
            result,
            Err(AppError::EmojiSetChanged { current_event_id_hex }) if current_event_id_hex == current
        )
    };
    assert!(changed(
        app.install_emoji_set(account, &fixture.set_coordinate, &shown, &control)
            .await
            .map(drop)
    ));
    assert!(changed(
        app.fetch_emoji_set_asset(account, &fixture.set_coordinate, &shown, "good")
            .await
            .map(drop)
    ));
    assert!(changed(
        app.fetch_emoji_set_cover(account, &fixture.set_coordinate, &shown)
            .await
            .map(drop)
    ));
    assert_eq!(host.requests(), 0, "no image request for an unseen version");
    assert_eq!(control.progress(), EmojiSetInstallProgress::default());
    fixture.assert_nothing_installed().await;

    // Shown again, the current version installs.
    host.serve(
        "/elsewhere.png",
        Canned::image("image/png", png(32, 32, None)),
    );
    let installed = app
        .install_emoji_set(account, &fixture.set_coordinate, &current, &control)
        .await
        .unwrap();
    assert_eq!(installed.installed_count, 1);
    assert_eq!(installed.set.installed.unwrap().event_id_hex, current);
    assert_eq!(host.requests(), 1);
}

/// A set's cover loads only on request, through the same image limits as
/// its emoji, and is not stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_set_cover_loads_only_on_request() {
    let fixture = fixture().await;
    let (app, account, host) = (&fixture.app, fixture.account(), &fixture.host);
    let covered = fixture.next_version_with(
        fixture.set_created_at,
        &[("good", "/good.png")],
        [tag(&["image", &host.url("/mislabeled.png")])],
    );
    fixture.publish(&covered).await;

    let set = app
        .fetch_emoji_set(account, &fixture.set_coordinate)
        .await
        .unwrap();
    assert_eq!(set.image_url, Some(host.url("/mislabeled.png")));
    assert_eq!(host.requests(), 0, "reading a set never loads its cover");

    let cover = app
        .fetch_emoji_set_cover(account, &fixture.set_coordinate, &set.event_id_hex)
        .await
        .unwrap();
    assert_eq!(
        (cover.mime.as_str(), cover.width, cover.height),
        ("image/png", 32, 32)
    );
    assert_eq!(cover.sha256, hex::encode(Sha256::digest(&cover.bytes)));
    assert_eq!(host.requests(), 1);

    host.serve(
        "/mislabeled.png",
        Canned::image("text/html", png(32, 32, None)),
    );
    assert!(matches!(
        app.fetch_emoji_set_cover(account, &fixture.set_coordinate, &set.event_id_hex)
            .await,
        Err(AppError::EmojiImageUnsupported(_))
    ));
    fixture.assert_nothing_installed().await;
}

/// Cancelling a reinstall mid-download drops the downloads in flight,
/// starts no more, and leaves the previous snapshot as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_reinstall_keeps_the_previous_snapshot() {
    let fixture = fixture().await;
    let (app, account, host) = (&fixture.app, fixture.account(), &fixture.host);
    app.sync_emoji_sets(account, None).await.unwrap();
    let first = fixture.shown_event_id().await;
    app.install_emoji_set(
        account,
        &fixture.set_coordinate,
        &first,
        &EmojiSetInstallControl::new(),
    )
    .await
    .unwrap();

    // Two quick entries, then four that never answer and fill the
    // download window, then more that must never be requested.
    host.serve("/slow.png", Canned::stalled());
    let mut entries = vec![("a", "/good.png"), ("b", "/mislabeled.png")];
    entries.extend([("c", "/slow.png"), ("d", "/slow.png"), ("e", "/slow.png")]);
    entries.extend([("f", "/slow.png"), ("g", "/good.png"), ("h", "/good.png")]);
    let next = fixture.next_version(fixture.set_created_at, &entries);
    fixture.publish(&next).await;
    let shown = app
        .fetch_emoji_set(account, &fixture.set_coordinate)
        .await
        .unwrap();
    assert_eq!(shown.event_id_hex, next.id.to_hex());

    let before = host.requests();
    let control = Arc::new(EmojiSetInstallControl::new());
    let install = tokio::spawn({
        let (app, account) = (app.clone(), account.to_owned());
        let (coordinate, control) = (fixture.set_coordinate.clone(), control.clone());
        async move {
            app.install_emoji_set(&account, &coordinate, &shown.event_id_hex, &control)
                .await
        }
    });
    wait_until("the stalled downloads", || {
        host.stalled_open.load(Ordering::SeqCst) == EMOJI_DOWNLOAD_CONCURRENCY
    })
    .await;
    let progress = control.progress();
    assert_eq!((progress.completed_emoji, progress.total_emoji), (2, 8));
    assert_eq!(host.requests() - before, 2 + EMOJI_DOWNLOAD_CONCURRENCY);

    control.cancel();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), install)
        .await
        .expect("a cancelled install returns promptly")
        .unwrap();
    assert!(
        matches!(result, Err(AppError::EmojiSetInstallCancelled)),
        "{result:?}"
    );
    wait_until("the in-flight downloads to drop", || {
        host.stalled_dropped.load(Ordering::SeqCst) == EMOJI_DOWNLOAD_CONCURRENCY
    })
    .await;
    // The install has returned and its download stream is gone: every
    // request it ever made was one of these.
    assert_eq!(
        host.requests() - before,
        2 + EMOJI_DOWNLOAD_CONCURRENCY,
        "no download starts after cancellation"
    );

    let installed = app.emoji_sets(account, true, None, None).await.unwrap();
    let state = installed[0].installed.as_ref().unwrap();
    assert_eq!(state.event_id_hex, first);
    assert!(state.update_available);
    assert_eq!(
        app.installed_custom_emoji(account)
            .await
            .unwrap()
            .iter()
            .map(|emoji| emoji.shortcode.as_str())
            .collect::<Vec<_>>(),
        vec!["good", "mislabeled"]
    );
    assert!(
        app.read_installed_custom_emoji(account, &fixture.set_coordinate, "good")
            .await
            .is_ok()
    );
}

/// Start an install whose only stalled download is in flight, run `stop`,
/// and check the install fails as cancelled, its control reads cancelled
/// and the download is dropped.
async fn stop_cancels_a_running_install<F, Fut>(stop: F) -> Fixture
where
    F: FnOnce(MarmotApp) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let fixture = fixture().await;
    let (app, account, host) = (&fixture.app, fixture.account(), &fixture.host);
    host.serve("/slow.png", Canned::stalled());
    let next = fixture.next_version(
        fixture.set_created_at,
        &[("a", "/good.png"), ("b", "/slow.png"), ("c", "/good.png")],
    );
    fixture.publish(&next).await;
    let shown = app
        .fetch_emoji_set(account, &fixture.set_coordinate)
        .await
        .unwrap()
        .event_id_hex;
    let control = Arc::new(EmojiSetInstallControl::new());
    let install = tokio::spawn({
        let (app, account) = (app.clone(), account.to_owned());
        let (coordinate, control) = (fixture.set_coordinate.clone(), control.clone());
        async move {
            app.install_emoji_set(&account, &coordinate, &shown, &control)
                .await
        }
    });
    wait_until("the stalled download", || {
        host.stalled_open.load(Ordering::SeqCst) == 1
    })
    .await;

    stop(app.clone()).await;

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), install)
        .await
        .expect("stopping cancels the install promptly")
        .unwrap();
    assert!(
        matches!(result, Err(AppError::EmojiSetInstallCancelled)),
        "{result:?}"
    );
    assert!(control.is_cancelled(), "the host reads the cancellation");
    wait_until("the in-flight download to drop", || {
        host.stalled_dropped.load(Ordering::SeqCst) == 1
    })
    .await;
    fixture
}

/// Runtime shutdown cancels a running install the way its control does,
/// stores nothing, and refuses later installs before any request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_shutdown_cancels_a_running_install() {
    let fixture = stop_cancels_a_running_install(|app| async move {
        crate::MarmotAppRuntime::new(app).shutdown().await;
    })
    .await;
    fixture.assert_nothing_installed().await;

    let shown = fixture.shown_event_id().await;
    let requests = fixture.host.requests();
    assert!(matches!(
        fixture
            .app
            .install_emoji_set(
                fixture.account(),
                &fixture.set_coordinate,
                &shown,
                &EmojiSetInstallControl::new()
            )
            .await,
        Err(AppError::EmojiSetInstallCancelled)
    ));
    assert_eq!(fixture.host.requests(), requests);
}

/// Closing storage, as `shutdown_and_close` does before a host suspends,
/// cancels a running install too, so nothing keeps downloading or reaches
/// the closing database.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_close_cancels_a_running_install() {
    stop_cancels_a_running_install(|app| async move {
        app.close_storage().unwrap();
    })
    .await;
}
