use super::*;
use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError};
use nostr::nips::nip44;
use nostr::nips::nip59::UnwrappedGift;
use nostr::prelude::{Event, Keys, ToBech32};
use std::sync::atomic::{AtomicUsize, Ordering};
use transport_nostr_adapter::{NostrPublishOutcome, NostrSubscription};

const REPORT_RELAY: &str = "wss://reports.example.com";
const SECOND_REPORT_RELAY: &str = "wss://reports-two.example.com";
const APP_RELAY: &str = "wss://relay.example";
const TWO_DAYS: u64 = 2 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Accept,
    Refuse,
    Unacknowledged,
    Hang,
}

/// Records every publish and answers with the scripted mode.
struct RecordingPublisher {
    mode: Mutex<Mode>,
    publishes: Mutex<Vec<(Vec<TransportEndpoint>, NostrTransportEvent)>>,
    started: tokio::sync::Notify,
    hung: AtomicUsize,
    /// When set, the next publish hangs regardless of `mode`.
    hang_next: std::sync::atomic::AtomicBool,
    /// Wrap ids refused regardless of `mode`.
    refused_ids: Mutex<std::collections::HashSet<String>>,
}

impl RecordingPublisher {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(mode),
            publishes: Mutex::new(Vec::new()),
            started: tokio::sync::Notify::new(),
            hung: AtomicUsize::new(0),
            hang_next: std::sync::atomic::AtomicBool::new(false),
            refused_ids: Mutex::default(),
        })
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn publishes(&self) -> Vec<(Vec<TransportEndpoint>, NostrTransportEvent)> {
        self.publishes.lock().unwrap().clone()
    }

    fn events(&self) -> Vec<NostrTransportEvent> {
        self.publishes()
            .into_iter()
            .map(|(_, event)| event)
            .collect()
    }
}

fn failures(
    endpoints: &[TransportEndpoint],
    kind: TransportEndpointFailureKind,
) -> Vec<TransportEndpointFailure> {
    endpoints
        .iter()
        .map(|endpoint| TransportEndpointFailure {
            endpoint: endpoint.clone(),
            reason: "scripted".into(),
            kind,
            rejection_category: None,
        })
        .collect()
}

#[async_trait]
impl NostrRelayClient for RecordingPublisher {
    async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.publishes
            .lock()
            .unwrap()
            .push((endpoints.to_vec(), event.clone()));
        self.started.notify_one();
        let mode = if self.hang_next.swap(false, Ordering::SeqCst) {
            Mode::Hang
        } else if self.refused_ids.lock().unwrap().contains(&event.id) {
            Mode::Refuse
        } else {
            *self.mode.lock().unwrap()
        };
        match mode {
            Mode::Accept => Ok(NostrPublishOutcome::accepted(endpoints.iter().cloned())),
            Mode::Refuse => Ok(NostrPublishOutcome {
                failed: failures(
                    endpoints,
                    TransportEndpointFailureKind::RetryableUnavailable,
                ),
                ..Default::default()
            }),
            Mode::Unacknowledged => Ok(NostrPublishOutcome {
                failed: failures(endpoints, TransportEndpointFailureKind::PossiblyExposed),
                ..Default::default()
            }),
            Mode::Hang => {
                self.hung.fetch_add(1, Ordering::SeqCst);
                std::future::pending().await
            }
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    reporter: Keys,
    moderation: Keys,
    publisher: Arc<RecordingPublisher>,
}

impl Fixture {
    fn configured(mode: Mode) -> Self {
        let fixture = Self::unconfigured(mode);
        fixture
            .app
            .set_moderation_report_config(Some(ModerationReportConfig {
                recipient_pubkey: fixture.moderation.public_key().to_hex(),
                relays: vec![REPORT_RELAY.into(), SECOND_REPORT_RELAY.into()],
            }))
            .unwrap();
        fixture
    }

    fn unconfigured(mode: Mode) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let reporter = Keys::generate();
        crate::AccountHome::open(dir.path())
            .import_account("alice", &reporter.secret_key().to_secret_hex())
            .unwrap();
        // Production relay policy: no loopback relays.
        let app = MarmotApp::with_relays_and_config(
            dir.path(),
            vec![APP_RELAY.into()],
            crate::MarmotAppConfig::default(),
        );
        let publisher = RecordingPublisher::new(mode);
        app.install_moderation_report_publisher_for_test(publisher.clone());
        Self {
            _dir: dir,
            app,
            reporter,
            moderation: Keys::generate(),
            publisher,
        }
    }

    async fn submit(
        &self,
        reported: &str,
        reason: ReportReason,
        explanation: &str,
        origin: ModerationReportOrigin,
    ) -> Result<ModerationReportOutcome, AppError> {
        self.app
            .submit_moderation_report("alice", reported, reason, explanation, origin, None)
            .await
    }

    async fn submit_at(
        &self,
        reported: &str,
        now_ms: u64,
    ) -> Result<(ModerationReportOutcome, bool), AppError> {
        self.app
            .submit_moderation_report_at(
                "alice",
                reported,
                ReportReason::Spam,
                "",
                ModerationReportOrigin::Report,
                None,
                now_ms,
            )
            .await
    }

    fn storage(&self) -> storage_sqlite::SqliteAccountStorage {
        self.app.account_storage("alice").unwrap()
    }

    fn pending(&self) -> Vec<ModerationReportOutboxEntry> {
        self.storage().pending_moderation_reports(100).unwrap()
    }
}

struct Unwrapped {
    wrap: Event,
    seal: Event,
    rumor: UnsignedEvent,
}

/// Decrypt every layer with the moderation team's key, checking each signature.
fn unwrap_with(moderation: &Keys, event: &NostrTransportEvent) -> Unwrapped {
    let wrap = event.to_verified_nostr_event().expect("wrap is signed");
    let seal_json = nip44::decrypt(moderation.secret_key(), &wrap.pubkey, &wrap.content).unwrap();
    let seal = Event::from_json(seal_json).unwrap();
    seal.verify().expect("seal is signed");
    let rumor_json = nip44::decrypt(moderation.secret_key(), &seal.pubkey, &seal.content).unwrap();
    let rumor = UnsignedEvent::from_json(rumor_json).unwrap();
    Unwrapped { wrap, seal, rumor }
}

fn now_secs() -> u64 {
    unix_now_ms() / 1000
}

fn tags(rumor: &UnsignedEvent) -> Vec<Vec<String>> {
    rumor
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect()
}

#[tokio::test]
async fn report_is_a_nip59_wrap_of_a_nip56_rumor_for_the_moderation_key() {
    let fixture = Fixture::configured(Mode::Accept);
    let reported = Keys::generate().public_key();
    let before = now_secs();
    let outcome = fixture
        .submit(
            &reported.to_hex(),
            ReportReason::Impersonation,
            "  pretends to be someone else  ",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, ModerationReportStatus::Published);
    assert_eq!(outcome.report_id.len(), 32);
    let after = now_secs();

    let events = fixture.publisher.events();
    assert_eq!(events.len(), 1);
    let Unwrapped { wrap, seal, rumor } = unwrap_with(&fixture.moderation, &events[0]);

    // Gift wrap: kind 1059, one-time key, single p tag to the moderation key.
    assert_eq!(wrap.kind, Kind::GiftWrap);
    assert_ne!(wrap.pubkey, fixture.reporter.public_key());
    assert_ne!(wrap.pubkey, fixture.moderation.public_key());
    assert_eq!(
        wrap.tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect::<Vec<_>>(),
        vec![vec![
            "p".to_owned(),
            fixture.moderation.public_key().to_hex()
        ]]
    );
    let wrap_at = wrap.created_at.as_secs();
    assert!(
        wrap_at <= after && wrap_at + TWO_DAYS >= before,
        "wrap timestamp outside NIP-59 bounds"
    );

    // Seal: kind 13, signed by the reporter, no tags, randomized into the past.
    assert_eq!(seal.kind, Kind::Seal);
    assert_eq!(seal.pubkey, fixture.reporter.public_key());
    assert!(seal.tags.is_empty());
    let seal_at = seal.created_at.as_secs();
    assert!(
        seal_at <= after && seal_at + TWO_DAYS >= before,
        "seal timestamp outside NIP-59 bounds"
    );

    // Rumor: unsigned kind 1984 by the reporter with exactly the NIP-56/NIP-32 tags.
    assert_eq!(rumor.kind, Kind::from(1984));
    assert_eq!(rumor.pubkey, fixture.reporter.public_key());
    assert!(rumor.created_at.as_secs() >= before && rumor.created_at.as_secs() <= after);
    assert_eq!(
        tags(&rumor),
        vec![
            vec![
                "p".to_owned(),
                reported.to_hex(),
                "impersonation".to_owned()
            ],
            vec!["L".to_owned(), "chat.whitenoise.report".to_owned()],
            vec![
                "l".to_owned(),
                "report".to_owned(),
                "chat.whitenoise.report".to_owned()
            ],
        ]
    );
    assert_eq!(rumor.content, "pretends to be someone else");

    // The library unwrap agrees and authenticates the reporter through the seal.
    let gift = UnwrappedGift::from_gift_wrap(&fixture.moderation, &wrap).unwrap();
    assert_eq!(gift.sender, fixture.reporter.public_key());
    assert_eq!(gift.rumor.content, rumor.content);
    // Nobody else can open it.
    assert!(UnwrappedGift::from_gift_wrap(&Keys::generate(), &wrap).is_err());
}

#[tokio::test]
async fn every_report_is_wrapped_by_a_fresh_one_time_key() {
    let fixture = Fixture::configured(Mode::Accept);
    for _ in 0..3 {
        fixture
            .submit(
                &Keys::generate().public_key().to_hex(),
                ReportReason::Spam,
                "",
                ModerationReportOrigin::Report,
            )
            .await
            .unwrap();
    }
    let wrap_keys = fixture
        .publisher
        .events()
        .iter()
        .map(|event| event.pubkey.clone())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(wrap_keys.len(), 3);
    assert!(!wrap_keys.contains(&fixture.reporter.public_key().to_hex()));
}

#[tokio::test]
async fn report_rumor_carries_no_conversation_identifiers() {
    let fixture = Fixture::configured(Mode::Accept);
    let reported = Keys::generate().public_key();
    fixture
        .submit(
            &reported.to_bech32().unwrap(),
            ReportReason::Other,
            "",
            ModerationReportOrigin::BlockAndReport,
        )
        .await
        .unwrap();
    let Unwrapped { rumor, .. } = unwrap_with(&fixture.moderation, &fixture.publisher.events()[0]);
    let names = tags(&rumor)
        .into_iter()
        .map(|tag| tag[0].clone())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["p", "L", "l"]);
    assert!(
        !names
            .iter()
            .any(|name| ["e", "h", "a", "q", "relays"].contains(&name.as_str()))
    );
    assert_eq!(rumor.content, "", "an empty explanation is omitted");
    assert_eq!(
        tags(&rumor)[2],
        vec!["l", "block", "chat.whitenoise.report"],
        "Block and Report is labelled block"
    );
    assert_eq!(
        tags(&rumor)[0],
        vec!["p".to_owned(), reported.to_hex(), "other".to_owned()]
    );
}

#[test]
fn explanation_is_trimmed_and_bounded() {
    assert_eq!(normalize_explanation("   "), "");
    assert_eq!(normalize_explanation("\n hello \t"), "hello");
    let long = format!(
        "  {}",
        "é".repeat(MODERATION_REPORT_EXPLANATION_MAX_CHARS + 500)
    );
    let bounded = normalize_explanation(&long);
    assert_eq!(
        bounded.chars().count(),
        MODERATION_REPORT_EXPLANATION_MAX_CHARS
    );
    let cut_at_space = format!(
        "{} tail",
        "a".repeat(MODERATION_REPORT_EXPLANATION_MAX_CHARS - 1)
    );
    assert_eq!(
        normalize_explanation(&cut_at_space),
        "a".repeat(MODERATION_REPORT_EXPLANATION_MAX_CHARS - 1)
    );
}

#[tokio::test]
async fn long_explanation_is_bounded_on_the_wire() {
    let fixture = Fixture::configured(Mode::Accept);
    fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Profanity,
            &"x".repeat(5_000),
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    let Unwrapped { rumor, .. } = unwrap_with(&fixture.moderation, &fixture.publisher.events()[0]);
    assert_eq!(
        rumor.content.chars().count(),
        MODERATION_REPORT_EXPLANATION_MAX_CHARS
    );
}

#[tokio::test]
async fn config_validation_rejects_the_whole_config() {
    let fixture = Fixture::unconfigured(Mode::Accept);
    let moderation = fixture.moderation.public_key();
    let config = |recipient: String, relays: &[&str]| ModerationReportConfig {
        recipient_pubkey: recipient,
        relays: relays.iter().map(|relay| (*relay).to_owned()).collect(),
    };
    let rejected = [
        config("not a key".into(), &[REPORT_RELAY]),
        config("ab".repeat(31), &[REPORT_RELAY]),
        config(
            fixture.reporter.secret_key().to_bech32().unwrap(),
            &[REPORT_RELAY],
        ),
        config(moderation.to_hex(), &[]),
        // One unsafe, malformed or retired relay rejects the whole config.
        config(moderation.to_hex(), &[REPORT_RELAY, "ws://10.0.0.1"]),
        config(moderation.to_hex(), &[REPORT_RELAY, "wss://127.0.0.1"]),
        config(
            moderation.to_hex(),
            &[REPORT_RELAY, "ws://reports.example.com"],
        ),
        config(
            moderation.to_hex(),
            &[REPORT_RELAY, "https://reports.example.com"],
        ),
        config(moderation.to_hex(), &[REPORT_RELAY, "not a url"]),
        config(
            moderation.to_hex(),
            &[REPORT_RELAY, "wss://relay.nostr.band"],
        ),
    ];
    for config in rejected {
        // A previously valid config must not survive a rejected replacement.
        fixture
            .app
            .set_moderation_report_config(Some(ModerationReportConfig {
                recipient_pubkey: moderation.to_hex(),
                relays: vec![REPORT_RELAY.into()],
            }))
            .unwrap();
        assert!(fixture.app.moderation_reporting_available());
        let error = fixture
            .app
            .set_moderation_report_config(Some(config.clone()))
            .expect_err(&format!("{config:?} must be rejected"));
        assert!(
            matches!(error, AppError::InvalidModerationReportConfig(_)),
            "{config:?} -> {error:?}"
        );
        assert!(!fixture.app.moderation_reporting_available(), "{config:?}");
    }

    // npub recipients are normalized; duplicate relays collapse.
    fixture
        .app
        .set_moderation_report_config(Some(config(
            moderation.to_bech32().unwrap(),
            &[REPORT_RELAY, "wss://REPORTS.example.com", REPORT_RELAY],
        )))
        .unwrap();
    let validated = fixture.app.moderation_report_config().unwrap();
    assert_eq!(validated.recipient, moderation);
    assert_eq!(validated.relays.len(), 1);

    fixture.app.set_moderation_report_config(None).unwrap();
    assert!(!fixture.app.moderation_reporting_available());
}

#[tokio::test]
async fn construction_time_config_is_adopted_or_rejected_whole() {
    let dir = tempfile::tempdir().unwrap();
    let moderation = Keys::generate().public_key();
    let valid = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![APP_RELAY.into()],
        crate::MarmotAppConfig::default().with_moderation_report_config(Some(
            ModerationReportConfig {
                recipient_pubkey: moderation.to_hex(),
                relays: vec![REPORT_RELAY.into()],
            },
        )),
    );
    assert!(valid.moderation_reporting_available());

    let invalid = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![APP_RELAY.into()],
        crate::MarmotAppConfig::default().with_moderation_report_config(Some(
            ModerationReportConfig {
                recipient_pubkey: moderation.to_hex(),
                relays: vec![REPORT_RELAY.into(), "ws://192.168.1.10".into()],
            },
        )),
    );
    assert!(!invalid.moderation_reporting_available());
}

#[tokio::test]
async fn unconfigured_reporting_is_a_typed_error_and_publishes_nothing() {
    let fixture = Fixture::unconfigured(Mode::Accept);
    let error = fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::ModerationReportingNotConfigured));
    assert!(fixture.publisher.publishes().is_empty());
    assert!(fixture.pending().is_empty());
    assert_eq!(
        fixture
            .storage()
            .moderation_reports_created_since(0)
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn reports_go_only_to_the_configured_relays() {
    let fixture = Fixture::configured(Mode::Accept);
    fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Illegal,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    let publishes = fixture.publisher.publishes();
    assert_eq!(publishes.len(), 1);
    let mut endpoints = publishes[0]
        .0
        .iter()
        .map(|endpoint| endpoint.0.trim_end_matches('/').to_owned())
        .collect::<Vec<_>>();
    endpoints.sort();
    assert_eq!(endpoints, vec![SECOND_REPORT_RELAY, REPORT_RELAY]);
}

#[tokio::test]
async fn refused_report_is_queued_and_published_on_retry() {
    let fixture = Fixture::configured(Mode::Refuse);
    let reported = Keys::generate().public_key();
    let outcome = fixture
        .submit(
            &reported.to_hex(),
            ReportReason::Malware,
            "a private explanation",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, ModerationReportStatus::AcceptedPending);

    // The queued row holds only ciphertext: no reported key, no explanation.
    let pending = fixture.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].report_id, outcome.report_id);
    let stored = pending[0].event_json.clone().unwrap();
    assert!(!stored.contains(&reported.to_hex()));
    assert!(!stored.contains("a private explanation"));
    assert!(!stored.contains(&fixture.reporter.public_key().to_hex()));

    // Still refused: stays queued.
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(
        summary,
        ModerationReportRetrySummary {
            published: 0,
            pending: 1,
            abandoned: 0
        }
    );

    fixture.publisher.set_mode(Mode::Accept);
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(summary.published, 1);
    assert!(fixture.pending().is_empty());

    // Every attempt carried the same wrap; no new gift wrap was minted.
    let ids = fixture
        .publisher
        .events()
        .into_iter()
        .map(|event| event.id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(fixture.publisher.publishes().len(), 3);
    assert_eq!(ids.len(), 1);

    // Nothing left to retry.
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(summary, ModerationReportRetrySummary::default());
}

#[tokio::test]
async fn unacknowledged_publish_reports_completion_unknown_and_stays_queued() {
    let fixture = Fixture::configured(Mode::Unacknowledged);
    let outcome = fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Nudity,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, ModerationReportStatus::CompletionUnknown);
    assert_eq!(fixture.pending().len(), 1);
}

#[tokio::test]
async fn repeat_inside_the_window_returns_the_existing_outcome() {
    let fixture = Fixture::configured(Mode::Refuse);
    let reported = Keys::generate().public_key().to_hex();
    let now = unix_now_ms();
    let (first, repeated) = fixture.submit_at(&reported, now).await.unwrap();
    assert!(!repeated);
    let (second, repeated) = fixture
        .submit_at(&reported, now + 9 * 60 * 1000)
        .await
        .unwrap();
    assert!(repeated);
    assert_eq!(second, first);
    assert_eq!(
        fixture.publisher.publishes().len(),
        1,
        "no second gift wrap"
    );

    // The repeat reflects the current state once the queued report publishes.
    fixture.publisher.set_mode(Mode::Accept);
    fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    let (third, repeated) = fixture
        .submit_at(&reported, now + 9 * 60 * 1000)
        .await
        .unwrap();
    assert!(repeated);
    assert_eq!(third.report_id, first.report_id);
    assert_eq!(third.status, ModerationReportStatus::Published);

    // A different reason or origin is a different report.
    let other_reason = fixture
        .submit(
            &reported,
            ReportReason::Illegal,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    assert_ne!(other_reason.report_id, first.report_id);
    let other_origin = fixture
        .submit(
            &reported,
            ReportReason::Spam,
            "",
            ModerationReportOrigin::BlockAndReport,
        )
        .await
        .unwrap();
    assert_ne!(other_origin.report_id, first.report_id);

    // After the window the same report is new again.
    let (later, repeated) = fixture
        .submit_at(&reported, now + 11 * 60 * 1000)
        .await
        .unwrap();
    assert!(!repeated);
    assert_ne!(later.report_id, first.report_id);
}

#[tokio::test]
async fn local_rate_limit_caps_reports_per_account() {
    let fixture = Fixture::configured(Mode::Accept);
    let now = unix_now_ms();
    for _ in 0..MODERATION_REPORT_RATE_LIMIT {
        fixture
            .submit_at(&Keys::generate().public_key().to_hex(), now)
            .await
            .unwrap();
    }
    let error = fixture
        .submit_at(&Keys::generate().public_key().to_hex(), now)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::ModerationReportRateLimited));
    assert_eq!(
        fixture.publisher.publishes().len() as u64,
        MODERATION_REPORT_RATE_LIMIT
    );
    // An idempotent repeat is not a new report and is not limited.
    // The window slides.
    let (_, repeated) = fixture
        .submit_at(
            &Keys::generate().public_key().to_hex(),
            now + 61 * 60 * 1000,
        )
        .await
        .unwrap();
    assert!(!repeated);
}

#[tokio::test]
async fn reporting_yourself_or_an_invalid_key_is_rejected() {
    let fixture = Fixture::configured(Mode::Accept);
    let own = fixture.reporter.public_key();
    for reported in [own.to_hex(), own.to_bech32().unwrap()] {
        let error = fixture
            .submit(
                &reported,
                ReportReason::Spam,
                "",
                ModerationReportOrigin::Report,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::CannotReportSelf), "{error:?}");
    }
    let nprofile = nostr::nips::nip19::Nip19Profile::new(Keys::generate().public_key(), [])
        .to_bech32()
        .unwrap();
    for reported in [
        "".to_owned(),
        "nope".to_owned(),
        "ab".repeat(31),
        "zz".repeat(32),
        nprofile,
        fixture.reporter.secret_key().to_bech32().unwrap(),
    ] {
        let error = fixture
            .submit(
                &reported,
                ReportReason::Spam,
                "",
                ModerationReportOrigin::Report,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::InvalidReportedPublicKey),
            "{reported}: {error:?}"
        );
    }
    assert!(fixture.publisher.publishes().is_empty());
}

#[tokio::test]
async fn signed_out_account_cannot_report() {
    let fixture = Fixture::configured(Mode::Accept);
    fixture
        .app
        .account_home()
        .set_account_signed_out("alice", true)
        .unwrap();
    let error = fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::AccountHome(AccountHomeError::SecretNotFound(_))
        ),
        "{error:?}"
    );
    assert!(fixture.publisher.publishes().is_empty());
}

#[tokio::test]
async fn purge_cancels_an_in_flight_publish_and_removes_queued_reports() {
    let fixture = Arc::new(Fixture::configured(Mode::Refuse));
    fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    assert_eq!(fixture.pending().len(), 1);

    fixture.publisher.set_mode(Mode::Hang);
    let submitting = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .submit(
                    &Keys::generate().public_key().to_hex(),
                    ReportReason::Illegal,
                    "",
                    ModerationReportOrigin::Report,
                )
                .await
        })
    };
    fixture.publisher.started.notified().await;
    while fixture.publisher.hung.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let removed = fixture.app.purge_moderation_reports("alice").await.unwrap();
    assert_eq!(removed, 2);
    let error = submitting.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        AppError::AccountHome(AccountHomeError::SecretNotFound(_))
    ));
    assert!(fixture.pending().is_empty());
    assert_eq!(
        fixture
            .storage()
            .moderation_reports_created_since(0)
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_stalled_retry_pass_blocks_neither_new_reports_nor_purge() {
    let fixture = Arc::new(Fixture::configured(Mode::Refuse));
    fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    fixture.publisher.set_mode(Mode::Accept);
    fixture.publisher.hang_next.store(true, Ordering::SeqCst);
    let retry = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .app
                .retry_pending_moderation_reports("alice", None)
                .await
        })
    };
    while fixture.publisher.hung.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    // A new report publishes while the retry pass is stuck on a relay.
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        fixture.submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Illegal,
            "",
            ModerationReportOrigin::Report,
        ),
    )
    .await
    .expect("submission is not blocked by a stalled retry")
    .unwrap();
    assert_eq!(outcome.status, ModerationReportStatus::Published);

    // An overlapping retry pass is skipped instead of double-publishing.
    let overlapping = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(overlapping, ModerationReportRetrySummary::default());

    // Purge does not wait for the stalled publish, and stops the pass.
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.app.purge_moderation_reports("alice"),
    )
    .await
    .expect("purge is not blocked by a stalled retry")
    .unwrap();
    let summary = retry.await.unwrap().unwrap();
    assert_eq!(summary.published, 0);
    assert!(fixture.pending().is_empty());
}

#[tokio::test]
async fn a_teardown_fence_closes_admission_until_the_sign_out_commits() {
    let fixture = Fixture::configured(Mode::Accept);
    let (fence, purged) = fixture.app.fence_moderation_reports("alice").await;
    assert_eq!(purged.unwrap(), 0);

    // The account is still signed in, but a report arriving mid-teardown is refused.
    let error = fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::AccountHome(AccountHomeError::SecretNotFound(_))
        ),
        "{error:?}"
    );
    assert_eq!(
        fixture
            .storage()
            .moderation_reports_created_since(0)
            .unwrap(),
        0
    );

    // A retry pass during teardown publishes nothing, even a row staged meanwhile.
    fixture
        .storage()
        .stage_moderation_report(&ModerationReportOutboxEntry {
            report_id: "a".repeat(32),
            dedupe_key: "d".repeat(64),
            recipient_pubkey_hex: fixture.moderation.public_key().to_hex(),
            outcome: ModerationReportOutboxOutcome::AcceptedPending,
            event_json: Some("{}".into()),
            created_at_ms: unix_now_ms(),
            attempts: 0,
        })
        .unwrap();
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(summary, ModerationReportRetrySummary::default());
    assert!(fixture.publisher.publishes().is_empty());

    // Once the sign-out commits, dropping the fence does not reopen admission.
    fixture
        .app
        .account_home()
        .set_account_signed_out("alice", true)
        .unwrap();
    drop(fence);
    let error = fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::AccountHome(AccountHomeError::SecretNotFound(_))
        ),
        "{error:?}"
    );
    assert!(fixture.publisher.publishes().is_empty());
}

#[tokio::test]
async fn a_failed_teardown_reopens_admission_when_its_fence_drops() {
    let fixture = Fixture::configured(Mode::Accept);
    let (fence, _) = fixture.app.fence_moderation_reports("alice").await;
    drop(fence);
    let outcome = fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, ModerationReportStatus::Published);
}

#[tokio::test]
async fn an_unacknowledged_report_stays_unknown_after_an_offline_retry() {
    let fixture = Fixture::configured(Mode::Unacknowledged);
    let reported = Keys::generate().public_key().to_hex();
    let now = unix_now_ms();
    let (first, _) = fixture.submit_at(&reported, now).await.unwrap();
    assert_eq!(first.status, ModerationReportStatus::CompletionUnknown);

    fixture.publisher.set_mode(Mode::Refuse);
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(summary.pending, 1);

    // The original wrap may already have reached the operator.
    let (repeat, repeated) = fixture.submit_at(&reported, now + 60_000).await.unwrap();
    assert!(repeated);
    assert_eq!(repeat.status, ModerationReportStatus::CompletionUnknown);
}

#[tokio::test]
async fn reports_that_keep_failing_do_not_starve_newer_ones() {
    let fixture = Fixture::configured(Mode::Refuse);
    let now = unix_now_ms();
    // A full batch of older reports, outside the current rate window...
    for _ in 0..RETRY_BATCH_LIMIT {
        fixture
            .submit_at(
                &Keys::generate().public_key().to_hex(),
                now - 2 * 60 * 60 * 1000,
            )
            .await
            .unwrap();
    }
    // ...and newer ones queued after them.
    for _ in 0..3 {
        fixture
            .submit_at(
                &Keys::generate().public_key().to_hex(),
                now - 30 * 60 * 1000,
            )
            .await
            .unwrap();
    }
    assert_eq!(fixture.pending().len(), RETRY_BATCH_LIMIT + 3);
    // The relay keeps refusing the older wraps but accepts the newer ones.
    {
        let events = fixture.publisher.events();
        let mut refused = fixture.publisher.refused_ids.lock().unwrap();
        for event in &events[..RETRY_BATCH_LIMIT] {
            refused.insert(event.id.clone());
        }
    }
    fixture.publisher.set_mode(Mode::Accept);

    let first = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    let second = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(
        first.published + second.published,
        3,
        "{first:?} {second:?}"
    );
    assert_eq!(fixture.pending().len(), RETRY_BATCH_LIMIT);
}

#[tokio::test]
async fn runtime_stop_leaves_the_report_queued_for_retry() {
    let fixture = Fixture::configured(Mode::Hang);
    let (stop, stopping) = watch::channel(false);
    let reported = Keys::generate().public_key().to_hex();
    let submit = fixture.app.submit_moderation_report(
        "alice",
        &reported,
        ReportReason::Spam,
        "",
        ModerationReportOrigin::Report,
        Some(stopping),
    );
    let stopper = async {
        fixture.publisher.started.notified().await;
        stop.send(true).unwrap();
    };
    let (outcome, ()) = tokio::join!(submit, stopper);
    let outcome = outcome.unwrap();
    // The wrap may already have reached a relay that never acknowledged it.
    assert_eq!(outcome.status, ModerationReportStatus::CompletionUnknown);
    let pending = fixture.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].report_id, outcome.report_id);
    assert_eq!(
        pending[0].outcome,
        ModerationReportOutboxOutcome::CompletionUnknown
    );

    // An offline retry cannot downgrade the interrupted attempt to pending.
    fixture.publisher.set_mode(Mode::Refuse);
    fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    let (repeat, repeated) = fixture
        .app
        .submit_moderation_report_at(
            "alice",
            &reported,
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
            None,
            unix_now_ms(),
        )
        .await
        .unwrap();
    assert!(repeated);
    assert_eq!(repeat.status, ModerationReportStatus::CompletionUnknown);

    fixture.publisher.set_mode(Mode::Accept);
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(summary.published, 1);
}

#[tokio::test]
async fn queued_reports_are_dropped_not_redirected_when_the_recipient_changes() {
    let fixture = Fixture::configured(Mode::Refuse);
    fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    fixture
        .app
        .set_moderation_report_config(Some(ModerationReportConfig {
            recipient_pubkey: Keys::generate().public_key().to_hex(),
            relays: vec![REPORT_RELAY.into()],
        }))
        .unwrap();
    fixture.publisher.set_mode(Mode::Accept);
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(
        summary,
        ModerationReportRetrySummary {
            published: 0,
            pending: 0,
            abandoned: 1
        }
    );
    assert_eq!(fixture.publisher.publishes().len(), 1);
}

#[tokio::test]
async fn retry_without_configuration_keeps_reports_queued() {
    let fixture = Fixture::configured(Mode::Refuse);
    fixture
        .submit(
            &Keys::generate().public_key().to_hex(),
            ReportReason::Spam,
            "",
            ModerationReportOrigin::Report,
        )
        .await
        .unwrap();
    fixture.app.set_moderation_report_config(None).unwrap();
    let summary = fixture
        .app
        .retry_pending_moderation_reports("alice", None)
        .await
        .unwrap();
    assert_eq!(summary.pending, 1);
    assert_eq!(fixture.publisher.publishes().len(), 1);
}

mod runtime {
    use super::*;
    use crate::runtime::{AccountSetupRequest, SignOutOptions};
    use crate::tests::{MemberResolutionDirectoryFetcher, ScriptedPushRelayClient};
    use crate::{MarmotAppRuntime, MarmotRelayPlane};

    const DIRECTORY: &str = "wss://directory.example";

    struct RuntimeFixture {
        _dir: tempfile::TempDir,
        app: MarmotApp,
        runtime: MarmotAppRuntime,
        account_id: String,
        label: String,
        publisher: Arc<RecordingPublisher>,
    }

    async fn runtime_fixture(mode: Mode) -> RuntimeFixture {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
        let mut app = MarmotApp::with_relay(dir.path(), DIRECTORY);
        app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
            Some(Duration::from_secs(120)),
            relay.clone(),
            fetcher,
            false,
        );
        let app = app.with_test_relay_client(relay);
        let publisher = RecordingPublisher::new(mode);
        app.install_moderation_report_publisher_for_test(publisher.clone());
        app.set_moderation_report_config(Some(ModerationReportConfig {
            recipient_pubkey: Keys::generate().public_key().to_hex(),
            relays: vec![REPORT_RELAY.into()],
        }))
        .unwrap();
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.unwrap();
        let account = runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![TransportEndpoint(DIRECTORY.into())],
                bootstrap_relays: vec![TransportEndpoint(DIRECTORY.into())],
                publish_initial_key_package: false,
                ..AccountSetupRequest::default()
            })
            .await
            .unwrap()
            .account;
        RuntimeFixture {
            _dir: dir,
            app,
            runtime,
            account_id: account.account_id_hex,
            label: account.label,
            publisher,
        }
    }

    impl RuntimeFixture {
        async fn queue_one(&self) -> ModerationReportOutcome {
            let outcome = self
                .runtime
                .submit_moderation_report(
                    &self.account_id,
                    &Keys::generate().public_key().to_hex(),
                    ReportReason::Spam,
                    "explanation",
                    ModerationReportOrigin::BlockAndReport,
                )
                .await
                .unwrap();
            assert_eq!(outcome.status, ModerationReportStatus::AcceptedPending);
            outcome
        }

        fn pending_count(&self) -> usize {
            self.app
                .account_storage(&self.label)
                .unwrap()
                .pending_moderation_reports(100)
                .unwrap()
                .len()
        }
    }

    #[tokio::test]
    async fn catch_up_retries_queued_reports_in_the_background() {
        let fixture = runtime_fixture(Mode::Refuse).await;
        assert!(fixture.runtime.moderation_reporting_available());
        fixture.queue_one().await;
        fixture.publisher.set_mode(Mode::Accept);
        let _ = fixture.runtime.catch_up_accounts().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while fixture.pending_count() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("catch-up published the queued report");
        assert_eq!(fixture.publisher.publishes().len(), 2);
    }

    #[tokio::test]
    async fn sign_out_purges_the_accounts_queued_reports() {
        let fixture = runtime_fixture(Mode::Refuse).await;
        fixture.queue_one().await;
        assert_eq!(fixture.pending_count(), 1);
        fixture
            .runtime
            .sign_out(
                &fixture.account_id,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(fixture.pending_count(), 0);
        assert_eq!(
            fixture
                .app
                .account_storage(&fixture.label)
                .unwrap()
                .moderation_reports_created_since(0)
                .unwrap(),
            0
        );
        // A signed-out account neither reports nor retries.
        let error = fixture
            .runtime
            .submit_moderation_report(
                &fixture.account_id,
                &Keys::generate().public_key().to_hex(),
                ReportReason::Spam,
                "",
                ModerationReportOrigin::Report,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AppError::AccountHome(AccountHomeError::SecretNotFound(_))
        ));
    }

    #[tokio::test]
    async fn wipe_removes_the_accounts_queued_reports() {
        let fixture = runtime_fixture(Mode::Refuse).await;
        fixture.queue_one().await;
        let outcome = fixture
            .runtime
            .sign_out_and_wipe(&fixture.account_id)
            .await
            .unwrap();
        assert!(outcome.local_cleanup.completed);
        assert!(
            fixture
                .app
                .account_home()
                .account(&fixture.account_id)
                .is_err()
        );
        // Nothing left to retry after the account is gone.
        fixture.publisher.set_mode(Mode::Accept);
        let _ = fixture.runtime.catch_up_accounts().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fixture.publisher.publishes().len(), 1);
    }
}
