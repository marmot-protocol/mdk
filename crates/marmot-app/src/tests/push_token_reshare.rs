//! Push-token re-share after a merged member add (mdk#2604). A member added
//! after a device's last token share cannot read that share, so every device
//! with a registration shares again once it merges the add.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::*;
use base64::Engine as _;
use cgka_traits::engine::SendIntent;
use std::collections::BTreeSet;
use std::str::FromStr as _;

const RELAY: &str = "wss://relay.example";

/// One device of a test account, with its own read position on the shared relay.
struct Device {
    label: String,
    account_id_hex: String,
    client: AppClient,
    cursor: usize,
}

impl Device {
    async fn create(home: &AccountHome, app: &MarmotApp, label: &str) -> Self {
        let account = home.create_account(label).unwrap();
        remember_test_member_inbox(app, &account.account_id_hex, RELAY);
        Self::open(app, label, &account.account_id_hex, 0).await
    }

    async fn open(app: &MarmotApp, label: &str, account_id_hex: &str, cursor: usize) -> Self {
        let mut client = app.client(label).await.unwrap();
        client.publish_key_package().await.unwrap();
        client.sync().await.unwrap();
        Self {
            label: label.to_owned(),
            account_id_hex: account_id_hex.to_owned(),
            client,
            cursor,
        }
    }

    async fn receive(&mut self, relay: &ScriptedPushRelayClient) {
        deliver_new(&mut self.client, relay, &mut self.cursor).await;
        self.client.sync().await.unwrap();
    }

    async fn join(&mut self, relay: &ScriptedPushRelayClient, group: &GroupId) {
        self.receive(relay).await;
        self.client.accept_group_invite(group).unwrap();
    }

    fn register(&self, raw_token: &str, server: &nostr::prelude::Keys) -> PushRegistration {
        let app = &self.client.app;
        app.set_native_push_enabled(&self.label, true).unwrap();
        app.upsert_push_registration(
            &self.label,
            PushPlatform::Fcm,
            raw_token,
            &server.public_key().to_hex(),
            Some(RELAY.to_owned()),
        )
        .unwrap()
    }

    fn registration(&self) -> PushRegistration {
        self.client
            .app
            .push_registration(&self.label)
            .unwrap()
            .unwrap()
    }

    async fn share(&mut self) -> PushRegistrationShareOutcome {
        self.client.share_push_registration().await.unwrap()
    }

    /// Groups queued for the current registration revision.
    fn pending_shares(&self) -> Vec<String> {
        let registration = self.registration();
        self.client
            .app
            .pending_push_registration_shares(
                &self.label,
                &registration.token_fingerprint,
                registration.updated_at_ms,
            )
            .unwrap()
    }

    fn leaf(&self, group: &GroupId) -> (String, u32) {
        (
            self.account_id_hex.clone(),
            self.client.runtime.own_leaf_index(group).unwrap(),
        )
    }

    /// A second connection to this device's database, for injecting faults.
    fn raw_connection(&self) -> rusqlite::Connection {
        let app = &self.client.app;
        let path = app.account_storage_path(&self.label);
        let keys = app.account_home().load_signing_keys(&self.label).unwrap();
        let key = app
            .sqlcipher_key(&self.label, &keys, &path, SqlcipherDatabaseKind::Session)
            .unwrap();
        let connection = rusqlite::Connection::open(path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        connection
    }

    /// `(member, leaf)` of every token record this device holds for `group`,
    /// its own record included.
    fn token_leaves(&self, group: &GroupId) -> BTreeSet<(String, u32)> {
        self.client
            .app
            .group_push_tokens(&self.label, &hex::encode(group.as_slice()))
            .unwrap()
            .into_iter()
            .map(|record| (record.member_id_hex, record.leaf_index))
            .collect()
    }
}

/// Provider tokens carried by the notification triggers published since `from`.
fn trigger_tokens(
    relay: &ScriptedPushRelayClient,
    from: usize,
    server: &nostr::prelude::Keys,
) -> BTreeSet<Vec<u8>> {
    let server_hex = server.public_key().to_hex();
    let server_secret =
        secp256k1::SecretKey::from_str(&server.secret_key().to_secret_hex()).unwrap();
    relay.published_events.lock().unwrap()[from..]
        .iter()
        .filter(|event| {
            event.kind == transport_nostr_peeler::KIND_NIP59_GIFT_WRAP
                && event.tags.iter().any(|tag| {
                    tag.first().is_some_and(|name| name == "p") && tag.get(1) == Some(&server_hex)
                })
        })
        .flat_map(|event| {
            let event = event.to_verified_nostr_event().unwrap();
            let gift = nostr::nips::nip59::extract_rumor(server, &event).unwrap();
            BASE64_STANDARD
                .decode(gift.rumor.content)
                .unwrap()
                .chunks_exact(notifications::PUSH_ENCRYPTED_TOKEN_LEN)
                // Anything that does not decrypt to a token is padding.
                .filter_map(|blob| {
                    notifications::decrypt_push_token_for_test(blob, &server_secret).ok()
                })
                .map(|(_, token)| token)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn group_message_count(relay: &ScriptedPushRelayClient) -> usize {
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .count()
}

/// Alice and Bob share tokens in a two-member group; Carol and Dave are not
/// yet members.
struct Fixture {
    _dir: tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
    server: nostr::prelude::Keys,
    group: GroupId,
    alice: Device,
    bob: Device,
    carol: Device,
    dave: Device,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = app_at(&dir, relay.clone());
        let server = nostr::prelude::Keys::generate();
        let mut alice = Device::create(&home, &app, "alice").await;
        let mut bob = Device::create(&home, &app, "bob").await;
        let carol = Device::create(&home, &app, "carol").await;
        let dave = Device::create(&home, &app, "dave").await;
        let group = alice
            .client
            .create_group("push re-share", &[&bob.account_id_hex])
            .await
            .unwrap();
        bob.join(&relay, &group).await;
        alice.register("alice-token", &server);
        bob.register("bob-token", &server);
        assert_eq!(alice.share().await.succeeded_groups, 1);
        assert_eq!(bob.share().await.succeeded_groups, 1);
        alice.receive(&relay).await;
        bob.receive(&relay).await;
        let both = BTreeSet::from([alice.leaf(&group), bob.leaf(&group)]);
        assert_eq!(alice.token_leaves(&group), both);
        assert_eq!(bob.token_leaves(&group), both);
        Self {
            _dir: dir,
            relay,
            server,
            group,
            alice,
            bob,
            carol,
            dave,
        }
    }

    fn group_hex(&self) -> String {
        hex::encode(self.group.as_slice())
    }
}

/// The issue's basic case: tokens shared before an add reach the new member,
/// and the new member's next trigger wakes the earlier members.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_added_after_token_shares_learns_every_existing_token() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let alice_shared = fx.alice.registration();
    assert!(
        fx.alice.pending_shares().is_empty(),
        "the shared revision is complete"
    );

    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    // The completed revision is queued again, not treated as already done.
    assert_eq!(fx.alice.pending_shares(), vec![fx.group_hex()]);
    fx.bob.receive(&relay).await;
    assert_eq!(fx.bob.pending_shares(), vec![fx.group_hex()]);

    fx.carol.join(&relay, &group).await;
    fx.carol.register("carol-token", &fx.server);
    for device in [&mut fx.alice, &mut fx.bob, &mut fx.carol] {
        let outcome = device.share().await;
        assert_eq!(outcome.attempted_groups, 1);
        assert_eq!(outcome.succeeded_groups, 1);
        assert_eq!(outcome.pending_groups, 0);
    }
    assert_eq!(
        fx.alice.registration().updated_at_ms,
        alice_shared.updated_at_ms,
        "the re-share republishes the same registration revision"
    );

    fx.carol.receive(&relay).await;
    let everyone = BTreeSet::from([
        fx.alice.leaf(&group),
        fx.bob.leaf(&group),
        fx.carol.leaf(&group),
    ]);
    assert_eq!(fx.carol.token_leaves(&group), everyone);

    let before = relay.published_events.lock().unwrap().len();
    fx.carol.client.send(&group, b"wake up").await.unwrap();
    assert_eq!(
        trigger_tokens(&relay, before, &fx.server),
        BTreeSet::from([b"alice-token".to_vec(), b"bob-token".to_vec()]),
    );
}

/// A member offline during two adds shares once after catching up past both,
/// and only merged adds queue a share.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_member_shares_once_after_catching_up_past_every_add() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();

    // A relay rejects the add's Commit, so it never merges.
    relay.reject_next_publish();
    assert!(
        fx.alice
            .client
            .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
            .await
            .is_err()
    );
    assert!(
        fx.alice.pending_shares().is_empty(),
        "an add that never merged queues nothing"
    );

    // Bob is offline: he reads nothing while Alice adds Carol, then Dave.
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.alice
        .client
        .invite_members(&group, &[fx.dave.account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(fx.alice.pending_shares(), vec![fx.group_hex()]);
    assert_eq!(fx.alice.share().await.succeeded_groups, 1);
    fx.carol.join(&relay, &group).await;
    fx.carol.receive(&relay).await;
    assert!(
        !fx.carol.token_leaves(&group).contains(&fx.bob.leaf(&group)),
        "Bob has not shared since Carol joined"
    );

    fx.bob.receive(&relay).await;
    assert_eq!(
        fx.bob.pending_shares(),
        vec![fx.group_hex()],
        "both adds collapse into one share"
    );
    let before = group_message_count(&relay);
    let outcome = fx.bob.share().await;
    assert_eq!(outcome.attempted_groups, 1);
    assert_eq!(outcome.succeeded_groups, 1);
    assert_eq!(group_message_count(&relay) - before, 1);

    fx.carol.receive(&relay).await;
    fx.dave.join(&relay, &group).await;
    for device in [&fx.carol, &fx.dave] {
        let leaves = device.token_leaves(&group);
        assert!(leaves.contains(&fx.alice.leaf(&group)));
        assert!(leaves.contains(&fx.bob.leaf(&group)));
    }
}

/// A share that fails to queue after this device's own add is retried, not
/// lost: own commands see member adds only once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_share_queue_after_own_add_is_retried() {
    let mut fx = Fixture::new().await;
    let group = fx.group.clone();
    let connection = fx.alice.raw_connection();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_share_queue BEFORE INSERT ON pending_push_registration_shares
             BEGIN SELECT RAISE(FAIL, 'injected share queue failure'); END;",
        )
        .unwrap();
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    assert!(fx.alice.pending_shares().is_empty());
    assert!(!fx.alice.client.take_queued_push_registration_share());
    fx.alice.client.retry_pending_member_add_push_shares();
    assert!(fx.alice.pending_shares().is_empty());

    connection
        .execute_batch("DROP TRIGGER fail_share_queue")
        .unwrap();
    fx.alice.client.retry_pending_member_add_push_shares();
    assert_eq!(fx.alice.pending_shares(), vec![fx.group_hex()]);
    assert!(fx.alice.client.take_queued_push_registration_share());
    assert!(fx.alice.client.pending_member_add_push_shares.is_empty());
}

/// A Commit that branch selection re-adopts after withdrawing it may restore
/// an add without a fresh `MemberAdded`, so its group is shared with again on
/// both the projection seam and the command boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readopted_commit_queues_a_share() {
    let mut fx = Fixture::new().await;
    let revalidated = cgka_traits::engine::GroupEvent::GroupStateRevalidated {
        group_id: fx.group.clone(),
        epoch: cgka_traits::EpochId(1),
        revalidated_commit_id: MessageId::new(vec![7; 32]),
    };
    fx.alice
        .client
        .observe_event_projection_effects(&revalidated, &mut SyncSummary::default())
        .unwrap();
    assert_eq!(fx.alice.pending_shares(), vec![fx.group_hex()]);
    assert!(fx.alice.client.take_queued_push_registration_share());

    fx.bob
        .client
        .queue_push_registration_shares_for_member_adds(std::slice::from_ref(&revalidated));
    assert_eq!(fx.bob.pending_shares(), vec![fx.group_hex()]);
    assert!(fx.bob.client.take_queued_push_registration_share());
}

/// The one-time upgrade repair queues every joined group again, so a member
/// that joined before the fix learns every token after the devices restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrade_repair_reaches_members_who_joined_before_the_fix() {
    let Fixture {
        _dir,
        relay,
        server,
        group,
        mut alice,
        mut bob,
        mut carol,
        ..
    } = Fixture::new().await;
    let group_hex = hex::encode(group.as_slice());
    alice
        .client
        .invite_members(&group, &[carol.account_id_hex.as_str()])
        .await
        .unwrap();
    bob.receive(&relay).await;
    // Model a pre-fix device: the add queued no share.
    for device in [&alice, &bob] {
        let registration = device.registration();
        assert!(
            device
                .client
                .app
                .complete_push_registration_share(
                    &device.label,
                    &group_hex,
                    &registration.token_fingerprint,
                    registration.updated_at_ms,
                )
                .unwrap()
        );
    }
    carol.join(&relay, &group).await;
    carol.register("carol-token", &server);
    carol.share().await;
    carol.receive(&relay).await;
    assert_eq!(
        carol.token_leaves(&group),
        BTreeSet::from([carol.leaf(&group)])
    );

    // Upgrade: the repair runs at open (twice here, to show a rerun is
    // harmless) and the restarted devices drain what it queued.
    let app = alice.client.app.clone();
    let reopened = [
        (
            alice.label.clone(),
            alice.account_id_hex.clone(),
            alice.cursor,
        ),
        (bob.label.clone(), bob.account_id_hex.clone(), bob.cursor),
    ];
    drop(alice);
    drop(bob);
    for (label, _, _) in &reopened {
        let storage = app.account_storage(label).unwrap().app_storage();
        storage.rerun_push_token_reshare_repair_for_test().unwrap();
        storage.rerun_push_token_reshare_repair_for_test().unwrap();
    }
    let mut leaves = BTreeSet::from([carol.leaf(&group)]);
    for (label, account_id_hex, cursor) in reopened {
        let mut device = Device::open(&app, &label, &account_id_hex, cursor).await;
        assert_eq!(device.pending_shares(), vec![group_hex.clone()]);
        assert!(
            !device
                .client
                .retry_pending_push_registration_shares_best_effort()
                .await
        );
        leaves.insert(device.leaf(&group));
    }
    carol.receive(&relay).await;
    assert_eq!(carol.token_leaves(&group), leaves);
}

/// Each device of an account re-shares its own leaf's record, so a new member
/// holds one record per sibling leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sibling_devices_reshare_their_own_records() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let sibling_dir = tempfile::tempdir().unwrap();
    let bob_secret = fx
        .bob
        .client
        .app
        .account_home()
        .load_signing_keys(&fx.bob.label)
        .unwrap()
        .secret_key()
        .to_secret_hex();
    AccountHome::open(sibling_dir.path())
        .import_account(&fx.bob.label, &bob_secret)
        .unwrap();
    let sibling_app = app_at(&sibling_dir, relay.clone());
    let tablet_cursor = relay.published_events.lock().unwrap().len();
    let mut tablet = Device::open(
        &sibling_app,
        &fx.bob.label,
        &fx.bob.account_id_hex,
        tablet_cursor,
    )
    .await;
    let key_package = published_key_package(&mut tablet.client, &relay).await;
    let effects = fx
        .alice
        .client
        .runtime
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    fx.alice
        .client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    tablet.join(&relay, &group).await;
    fx.bob.receive(&relay).await;
    tablet.register("bob-tablet-token", &fx.server);
    assert_eq!(tablet.share().await.succeeded_groups, 1);
    assert_ne!(tablet.leaf(&group), fx.bob.leaf(&group));

    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.bob.receive(&relay).await;
    tablet.receive(&relay).await;
    fx.carol.join(&relay, &group).await;
    for device in [&mut fx.alice, &mut fx.bob, &mut tablet] {
        assert_eq!(device.share().await.succeeded_groups, 1);
    }
    fx.carol.receive(&relay).await;
    let carol_records = fx
        .carol
        .client
        .app
        .group_push_tokens(&fx.carol.label, &fx.group_hex())
        .unwrap()
        .into_iter()
        .map(|record| {
            (
                record.member_id_hex,
                record.leaf_index,
                record.token_fingerprint,
            )
        })
        .collect::<BTreeSet<_>>();
    let record = |device: &Device| {
        let (member, leaf) = device.leaf(&group);
        (member, leaf, device.registration().token_fingerprint)
    };
    assert_eq!(
        carol_records,
        BTreeSet::from([record(&fx.alice), record(&fx.bob), record(&tablet)])
    );
}
