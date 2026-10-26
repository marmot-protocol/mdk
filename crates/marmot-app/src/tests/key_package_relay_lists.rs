//! A KeyPackage publish never replaces relay lists the identity already
//! published. Kinds 10002 and 10050 are replaceable, so the app reads them
//! before publishing its own relays and publishes only a kind a complete read
//! proves absent (mdk#2550).

use std::time::Duration;

use cgka_traits::TransportEndpoint;
use marmot_account::{AccountHome, AccountSummary};

use crate::{AccountRelayListStatus, AppError, MarmotApp, MissingRelayListKind};

async fn mock_relay() -> (nostr_relay_builder::MockRelay, String) {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

/// The identity's own device, which published its lists before this app ever
/// saw the identity.
struct SourceDevice {
    _directory: tempfile::TempDir,
    app: MarmotApp,
    account: AccountSummary,
    secret: String,
}

impl SourceDevice {
    fn new(relay_url: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let secret = nostr::prelude::Keys::generate()
            .secret_key()
            .to_secret_hex();
        let account = AccountHome::open(directory.path())
            .import_nostr_account(&secret)
            .unwrap();
        let app = MarmotApp::with_relay(directory.path(), relay_url.to_owned());
        Self {
            _directory: directory,
            app,
            account,
            secret,
        }
    }

    async fn publish(
        &self,
        through: &TransportEndpoint,
        read: Vec<TransportEndpoint>,
        write: Vec<TransportEndpoint>,
        inbox: Vec<TransportEndpoint>,
    ) -> AccountRelayListStatus {
        self.app
            .publish_account_nip65_relay_set(
                &self.account.label,
                read,
                write,
                vec![through.clone()],
            )
            .await
            .unwrap();
        self.app
            .publish_account_relay_list_kind(
                &self.account.label,
                "inbox",
                inbox,
                vec![through.clone()],
            )
            .await
            .unwrap();
        // A replacement published later must land in a later second, or
        // same-second ordering could hide it.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        self.app
            .account_relay_list_status(&self.account.label)
            .unwrap()
    }

    async fn on_relay(&self, relay: &TransportEndpoint) -> AccountRelayListStatus {
        self.app
            .directory()
            .fetch_current_account_relay_list_status_for_account_id(
                &self.account.account_id_hex,
                vec![relay.clone()],
                None,
            )
            .await
            .unwrap()
            .expect("published relay lists")
    }
}

/// Import `secret` offline into a fresh home, so the app has no cached copy of
/// either list.
fn import_offline(secret: &str, relay_url: &str) -> (tempfile::TempDir, MarmotApp, String) {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .import_nostr_account(secret)
        .unwrap();
    let app = MarmotApp::with_relay(directory.path(), relay_url.to_owned());
    assert!(
        !app.account_relay_list_status(&account.label)
            .unwrap()
            .complete,
        "the offline import must start without cached relay lists"
    );
    (directory, app, account.label)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_package_publish_adopts_relay_lists_an_imported_identity_already_published() {
    let (_relay, relay_url) = mock_relay().await;
    let (_read_relay, read_url) = mock_relay().await;
    let (_write_relay, write_url) = mock_relay().await;
    let (_inbox_relay, inbox_url) = mock_relay().await;
    let relay = TransportEndpoint(relay_url.clone());
    let source = SourceDevice::new(&relay_url);
    let published = source
        .publish(
            &relay,
            vec![relay.clone(), TransportEndpoint(read_url.clone())],
            vec![relay.clone(), TransportEndpoint(write_url.clone())],
            vec![relay.clone(), TransportEndpoint(inbox_url.clone())],
        )
        .await;
    let (_directory, app, label) = import_offline(&source.secret, &relay_url);

    app.client(&label)
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();

    // The relay still serves the lists the identity published, not a
    // replacement naming only the app's relay.
    let on_relay = source.on_relay(&relay).await;
    assert_eq!(on_relay.nip65.created_at, published.nip65.created_at);
    assert_eq!(on_relay.inbox.created_at, published.inbox.created_at);
    assert!(on_relay.nip65.read_relays.contains(&read_url));
    assert!(on_relay.nip65.write_relays.contains(&write_url));
    assert!(on_relay.inbox.relays.contains(&inbox_url));

    // This home adopted them.
    let adopted = app.account_relay_list_status(&label).unwrap();
    assert!(adopted.complete);
    assert_eq!(adopted.nip65.created_at, published.nip65.created_at);
    assert_eq!(adopted.inbox.created_at, published.inbox.created_at);
    assert!(adopted.inbox.relays.contains(&inbox_url));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_package_publish_keeps_a_read_only_nip65_list() {
    // A kind 10002 with only a read relay has no write route, so MDK counts it
    // as missing. That is not absence: neither the first publish, which reads
    // it, nor a retry, which finds it cached, may replace it.
    let (_relay, relay_url) = mock_relay().await;
    let (_read_relay, read_url) = mock_relay().await;
    let (_inbox_relay, inbox_url) = mock_relay().await;
    let relay = TransportEndpoint(relay_url.clone());
    let source = SourceDevice::new(&relay_url);
    let published = source
        .publish(
            &relay,
            vec![TransportEndpoint(read_url.clone())],
            Vec::new(),
            vec![TransportEndpoint(inbox_url.clone())],
        )
        .await;
    assert_eq!(published.nip65.read_relays, vec![read_url.clone()]);
    assert!(published.nip65.write_relays.is_empty());
    let (_directory, app, label) = import_offline(&source.secret, &relay_url);

    let mut client = app.client(&label).await.unwrap();
    for attempt in ["first", "retry"] {
        let error = client.publish_key_package().await.unwrap_err();
        assert!(
            matches!(error, AppError::MissingRelayLists(ref kinds) if kinds == &[MissingRelayListKind::Nip65]),
            "{attempt} publish: {error:?}"
        );
    }

    let on_relay = source.on_relay(&relay).await;
    assert_eq!(on_relay.nip65.created_at, published.nip65.created_at);
    assert_eq!(on_relay.nip65.read_relays, vec![read_url]);
    assert!(on_relay.nip65.write_relays.is_empty());
    assert_eq!(on_relay.inbox.created_at, published.inbox.created_at);
    assert_eq!(on_relay.inbox.relays, vec![inbox_url]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_package_publish_publishes_app_relay_lists_once_their_absence_is_read() {
    let (_relay, relay_url) = mock_relay().await;
    let relay = TransportEndpoint(relay_url.clone());
    let secret = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex();
    let (_directory, app, label) = import_offline(&secret, &relay_url);

    // The app's relay answered and holds no list: absence is established, so
    // the app publishes its own relays.
    app.client(&label)
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();

    let reader = tempfile::tempdir().unwrap();
    let account_id_hex = app.account_home().account(&label).unwrap().account_id_hex;
    let published = MarmotApp::with_relay(reader.path(), relay_url.clone())
        .directory()
        .fetch_current_account_relay_list_status_for_account_id(&account_id_hex, vec![relay], None)
        .await
        .unwrap()
        .expect("published relay lists");
    assert_eq!(published.nip65.relays, vec![relay_url.clone()]);
    assert_eq!(published.inbox.relays, vec![relay_url]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_package_publish_publishes_no_relay_list_when_an_app_relay_cannot_answer() {
    let (_relay, relay_url) = mock_relay().await;
    // A loopback port nothing listens on: that relay cannot confirm absence.
    let unreachable_url = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("ws://{}", listener.local_addr().unwrap())
    };
    let secret = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex();
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .import_nostr_account(&secret)
        .unwrap();
    let app = MarmotApp::with_relays(directory.path(), vec![relay_url.clone(), unreachable_url]);

    let error = app
        .client(&account.label)
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::DirectoryLookupIncomplete(_)),
        "{error:?}"
    );

    // The reachable relay received no list: an unconfirmed read never turns
    // into a replacement.
    let reader = tempfile::tempdir().unwrap();
    let published = MarmotApp::with_relay(reader.path(), relay_url.clone())
        .directory()
        .fetch_current_account_relay_list_status_for_account_id(
            &account.account_id_hex,
            vec![TransportEndpoint(relay_url)],
            None,
        )
        .await
        .unwrap();
    assert!(published.is_none(), "{published:?}");
    assert!(
        !app.account_relay_list_status(&account.label)
            .unwrap()
            .complete
    );
}
