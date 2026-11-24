//! Owed Welcomes whose recipient has no inbox route (mdk#2261): why the
//! route is missing, and the session's pacing of the recipient's retries.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

const BOB_INBOX: &str = "wss://bob-inbox.example";
const BOB_NEW_INBOX: &str = "wss://bob-new-inbox.example";

/// The session's wall clock, moved by the test.
struct TestClock(AtomicU64);

impl marmot_session::WallClock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }

    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst) * 1_000
    }
}

/// Cache `account`'s inbox list naming `relays`, signed at `created_at`, as
/// any directory read that observes it does.
fn remember_inbox(app: &MarmotApp, account: &str, relays: &[&str], created_at: u64) {
    let mut lists = AccountRelayListStatus::empty();
    lists.inbox.created_at = created_at;
    lists.inbox.relays = relays.iter().map(|relay| (*relay).to_owned()).collect();
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(account, &lists)
        .unwrap();
}

/// The v5 rows of `kind`, oldest first.
fn v5_rows(app: &MarmotApp, kind: &str) -> Vec<serde_json::Value> {
    app.audit_log_files()
        .unwrap()
        .iter()
        .flat_map(|file| {
            std::fs::read_to_string(&file.path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>()
        })
        .filter(|row| row["event"]["type"] == kind)
        .collect()
}

fn not_started_reasons(app: &MarmotApp) -> Vec<String> {
    v5_rows(app, "welcome_publish_not_started")
        .iter()
        .map(|row| row["event"]["reason"].as_str().unwrap().to_owned())
        .collect()
}

/// Why a member has no inbox route, from what the directory cache holds of
/// their inbox list: nothing, a signed list naming no relay, or relays the
/// host-safety rule refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_inbox_route_says_why() {
    use MissingInboxRouteCause::*;
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let remembered = |relays: &[&str]| {
        let account = Keys::generate().public_key().to_hex();
        remember_inbox(&app, &account, relays, 5);
        account
    };
    let unknown = Keys::generate().public_key().to_hex();
    let empty = remembered(&[]);
    let unusable = remembered(&["wss://10.1.2.3"]);
    let usable = remembered(&["wss://inbox.example"]);

    assert_eq!(app.member_inbox_route(&unknown).unwrap(), Err(NoList));
    assert_eq!(app.member_inbox_route(&empty).unwrap(), Err(EmptyList));
    assert_eq!(app.member_inbox_route(&unusable).unwrap(), Err(NoneUsable));
    assert!(app.member_inbox_route(&usable).unwrap().is_ok());
}

/// An invite's Welcome no relay took, whose recipient's cached inbox list is
/// empty by the time its 24-hour retry record expires, is classified and
/// paced (mdk#2261): a pass inside the 10-minute wait records no failure, and
/// the first pass after it sends the Welcome to a list that reached the cache
/// meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_less_welcome_is_classified_and_paced() {
    let bob_dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_id = bob.account_id_hex.clone();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let bob_app = MarmotApp::with_relay(bob_dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let key_package = fresh_key_package_for_account(&bob_app, &bob, false).await;

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let now = unix_now_seconds();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    fetcher.events.lock().unwrap().extend([
        member_resolution_key_package_event(&bob, key_package),
        NostrTransportEvent::new_unsigned_at(
            bob_id.clone(),
            KIND_NIP65_RELAY_LIST,
            vec![vec!["r".into(), "wss://shared.example".into()]],
            String::new(),
            now - 100,
        ),
        NostrTransportEvent::new_unsigned_at(
            bob_id.clone(),
            KIND_MARMOT_INBOX_RELAY_LIST,
            vec![vec!["relay".into(), BOB_INBOX.into()]],
            String::new(),
            now - 100,
        ),
    ]);
    let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.relay_plane =
        MarmotRelayPlane::new_with_directory_fetcher_for_test(None, relay.clone(), fetcher, false);
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    relay.make_endpoints_unavailable(&[BOB_INBOX]);
    let mut alice = app.client("alice").await.unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(now)));
    alice.runtime = alice.runtime.with_maintenance_sources(
        clock.clone(),
        Arc::new(marmot_session::SystemMonotonicClock::default()),
        Arc::new(marmot_session::OsMaintenanceRandom),
    );
    alice
        .create_group("paced", &[&bob_id])
        .await
        .unwrap()
        .operation
        .expect("bob is eligible");
    assert_eq!(
        alice.pending_welcome_deliveries().unwrap().len(),
        1,
        "no relay took the Welcome"
    );

    // Bob's newer, empty list reaches the cache and the routing table, as a
    // directory read followed by a routing refresh installs it.
    remember_inbox(&app, &bob_id, &[], now - 50);
    alice.refresh_routing().unwrap();
    let expired = now + 25 * 60 * 60;
    clock.0.store(expired, Ordering::SeqCst);
    alice.run_due_maintenance().await.unwrap();
    assert_eq!(not_started_reasons(&app), ["no_eligible_route"]);

    clock.0.store(expired + 599, Ordering::SeqCst);
    let failures = v5_rows(&app, "publish_failure").len();
    alice.run_due_maintenance().await.unwrap();
    assert_eq!(
        v5_rows(&app, "publish_failure").len(),
        failures,
        "a pass inside the wait records no failure"
    );
    assert_eq!(not_started_reasons(&app).len(), 1);

    // A new list arrives the same way, as a new invite to Bob would bring it.
    remember_inbox(&app, &bob_id, &[BOB_NEW_INBOX], now);
    alice.refresh_routing().unwrap();
    clock.0.store(expired + 600, Ordering::SeqCst);
    alice.run_due_maintenance().await.unwrap();
    assert!(
        alice.pending_welcome_deliveries().unwrap().is_empty(),
        "the Welcome went out to Bob's new inbox"
    );
    assert!(
        relay
            .attempted_publish_routes
            .lock()
            .unwrap()
            .iter()
            .any(|(kind, endpoints)| *kind == 1059
                && endpoints
                    .iter()
                    .any(|endpoint| endpoint.0.starts_with(BOB_NEW_INBOX)))
    );
    assert_eq!(not_started_reasons(&app).len(), 1);
}
