//! What A reuses across versions (mdk#3273 PR 2): group entries and the owned
//! KeyPackage list, each until its validity stops holding.

#[cfg(feature = "test-policy-overrides")]
use super::canonical_membership::deliver_new;
#[cfg(feature = "test-policy-overrides")]
use super::push_token_reshare::Device;
use super::*;
use crate::client::read_state::oracle::{KeyPackageInputs, LifetimeBound};
use crate::client::read_state::{GroupAnswers, ReadState, UploadsInFlight};
use tokio::sync::watch;

fn entry(state: &watch::Receiver<Arc<ReadState>>, group: &GroupId) -> (u64, Arc<GroupAnswers>) {
    let state = state.borrow();
    (state.version, state.groups[group].clone())
}

/// An application message advances only the message ratchet and stores the
/// message, which no answer in A holds, so the next publish keeps the group's
/// entry and the version; a commit replaces the entry.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_application_message_keeps_the_group_entry_and_a_commit_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut alice = Device::create(&home, &app, "alice").await;
    let mut bob = Device::create(&home, &app, "bob").await;
    let group = alice
        .client
        .create_group("cached entry", &[&bob.account_id_hex])
        .await
        .unwrap();
    bob.join(&relay, &group).await;
    bob.client.start_read_state(UploadsInFlight::default());
    let state = bob.client.subscribe_read_state().unwrap();
    let (version, joined) = entry(&state, &group);

    alice.client.send(&group, b"cached").await.unwrap();
    let received = deliver_new(&mut bob.client, &relay, &mut bob.cursor).await;
    assert_eq!(received.messages.len(), 1);
    bob.client.publish_read_state();
    let (after_message, kept) = entry(&state, &group);
    assert_eq!(after_message, version, "the stored message moved no answer");
    assert!(Arc::ptr_eq(&joined, &kept));

    alice
        .client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap();
    deliver_new(&mut bob.client, &relay, &mut bob.cursor).await;
    bob.client.publish_read_state();
    let (_, renamed) = entry(&state, &group);
    assert!(!Arc::ptr_eq(&joined, &renamed));
}

/// Commit delivery reads only the group's outbound fanouts, so retiring the
/// fanout of a commit a relay still owes is a write to nothing else the
/// entry holds. The publish after it rebuilds the entry, and the oracle that
/// checks every changed publish under test agrees with the live read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fanout_write_alone_rebuilds_the_group_entry() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays(
        dir.path(),
        vec![
            "wss://relay-a.example".to_owned(),
            "wss://relay-b.example".to_owned(),
        ],
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("owed", &[]).await.unwrap();
    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    client
        .update_group_profile(&group, Some("owed"), None)
        .await
        .unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (_, owed) = entry(&state, &group);
    assert!(
        state
            .borrow()
            .group_commit_delivery(&group)
            .unwrap()
            .is_some()
    );

    let session = client.runtime.session();
    for fanout in session.outbound_fanouts_for_group(&group).unwrap() {
        session.delete_outbound_fanout(fanout.message_id()).unwrap();
    }
    client.publish_read_state();
    let (_, retired) = entry(&state, &group);
    assert!(!Arc::ptr_eq(&owed, &retired));
    assert_eq!(state.borrow().group_commit_delivery(&group).unwrap(), None);
}

/// One unkeyed delete that retires fanouts of two groups, as a bulk path
/// would, is one write per row: the publish after it rebuilds both entries,
/// and the oracle agrees with the live read for each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bulk_delete_rebuilds_every_group_entry_it_touches() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays(
        dir.path(),
        vec![
            "wss://relay-a.example".to_owned(),
            "wss://relay-b.example".to_owned(),
        ],
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let groups = [
        client.create_group("first", &[]).await.unwrap(),
        client.create_group("second", &[]).await.unwrap(),
    ];
    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    for group in &groups {
        client
            .update_group_profile(group, Some("owed"), None)
            .await
            .unwrap();
    }
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let owed: Vec<_> = groups.iter().map(|group| entry(&state, group).1).collect();
    for group in &groups {
        assert!(
            state
                .borrow()
                .group_commit_delivery(group)
                .unwrap()
                .is_some()
        );
    }

    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test("DELETE FROM cgka_outbound_fanout")
        .unwrap();
    client.publish_read_state();
    for (group, owed) in groups.iter().zip(owed) {
        assert!(!Arc::ptr_eq(&owed, &entry(&state, group).1));
        assert_eq!(state.borrow().group_commit_delivery(group).unwrap(), None);
    }
}

/// A failed account read can clear with no write to the database, so A
/// rebuilds account answers at every publish instead of keeping a failure
/// until something writes. Here a TEMP table on the app's connection shadows
/// the prepared-uploads table, failing that read without writing the
/// database, and then goes away.
#[tokio::test]
async fn a_failed_account_read_recovers_without_a_write() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let storage = app.account_storage("alice").unwrap().app_storage();

    storage
        .execute_batch_for_test(
            "CREATE TEMP TABLE app_prepared_group_image_upload (shadow INTEGER)",
        )
        .unwrap();
    client.publish_read_state();
    assert!(state.borrow().account.prepared_group_images.is_err());

    storage
        .execute_batch_for_test("DROP TABLE temp.app_prepared_group_image_upload")
        .unwrap();
    client.publish_read_state();
    assert!(state.borrow().account.prepared_group_images.is_ok());
}

/// The owned KeyPackage list is the one account answer A reuses: its read
/// re-checks every stored bundle's signatures. It is kept while the account
/// database's total write count holds, which every write to the file moves
/// through any connection: here bundles change through the app's own
/// connection, not the engine. The version carries the list's lifetime bound,
/// and a read that skipped a bundle that does not decode is never reused. The
/// oracle checks a settled reuse by the list's inputs, without reading the
/// list afresh.
#[tokio::test]
async fn the_owned_key_package_list_is_reused_only_until_the_file_is_written() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let owned = state
        .borrow()
        .account
        .durably_owned_key_packages
        .clone()
        .unwrap();
    assert_eq!(owned.len(), 1);
    let not_after = cgka_engine::key_package::key_package_metadata(&owned[0])
        .unwrap()
        .not_after;
    assert_eq!(state.borrow().valid_until, Some(Timestamp(not_after)));

    client.publish_read_state();
    assert!(client.read_state_reused_key_packages());
    assert!(!client.read_state_read_key_packages_afresh());

    let storage = app.account_storage("alice").unwrap().app_storage();
    storage
        .execute_batch_for_test(
            "DELETE FROM openmls_values WHERE label = CAST('KeyPackage' AS BLOB)",
        )
        .unwrap();
    client.publish_read_state();
    assert!(!client.read_state_reused_key_packages());
    let state_now = state.borrow().clone();
    assert!(
        state_now
            .account
            .durably_owned_key_packages
            .as_ref()
            .unwrap()
            .is_empty()
    );
    assert_eq!(state_now.valid_until, None);

    storage
        .execute_batch_for_test(
            "INSERT INTO openmls_values (provider_version, label, storage_key, value)
             VALUES (1, CAST('KeyPackage' AS BLOB), x'00ff', x'00')",
        )
        .unwrap();
    client.publish_read_state();
    client.publish_read_state();
    assert!(!client.read_state_reused_key_packages());
}

/// A stored bundle that is not valid yet stays out of the owned list, but its
/// `not_before` bounds the list, so the publish moves `valid_until` alone and
/// carries the time the list next changes with no write.
#[tokio::test]
async fn a_bundle_not_valid_yet_bounds_the_list_it_stays_out_of() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (version, published) = {
        let state = state.borrow();
        (
            state.version,
            state.account.durably_owned_key_packages.clone().unwrap(),
        )
    };

    let not_before = crate::unix_now_seconds() + 3_600;
    store_own_bundle_valid_from(&app, &published[0], not_before);
    client.publish_read_state();
    let state = state.borrow();
    assert_eq!(
        state.account.durably_owned_key_packages.as_ref().unwrap(),
        &published
    );
    assert_eq!(state.valid_until, Some(Timestamp(not_before)));
    assert!(state.version > version);
}

/// The oracle skips its fresh read of a reused KeyPackage list only while
/// the list's raw inputs are the ones read before its build and the clock is
/// at or after that reading and short of the first lifetime bound after it:
/// the soonest `not_after` of a stored bundle, or `not_before` of one not
/// valid yet, decoded without OpenMLS. A stored row whose lifetime it cannot
/// find never lets it skip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_oracle_rereads_a_reused_key_package_list_once_an_input_or_the_clock_moves() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    let published = client.durably_owned_key_packages().unwrap();
    let not_after = cgka_engine::key_package::key_package_metadata(&published[0])
        .unwrap()
        .not_after;

    let built_from = KeyPackageInputs::read(&client).unwrap();
    assert_eq!(
        built_from.first_bound(),
        LifetimeBound::At(Timestamp(not_after))
    );
    let mut now = KeyPackageInputs::read(&client).unwrap();
    assert!(built_from.holds_at(&now));
    now.taken_at = Timestamp(not_after);
    assert!(!built_from.holds_at(&now));
    now.taken_at = Timestamp(built_from.taken_at.0 - 1);
    assert!(!built_from.holds_at(&now));

    let not_before = crate::unix_now_seconds() + 3_600;
    store_own_bundle_valid_from(&app, &published[0], not_before);
    let with_new_bundle = KeyPackageInputs::read(&client).unwrap();
    assert!(!built_from.holds_at(&with_new_bundle));
    assert_eq!(
        with_new_bundle.first_bound(),
        LifetimeBound::At(Timestamp(not_before))
    );

    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test(
            "INSERT INTO openmls_values (provider_version, label, storage_key, value)
             VALUES (1, CAST('KeyPackage' AS BLOB), x'00ff', x'00')",
        )
        .unwrap();
    let undecodable = KeyPackageInputs::read(&client).unwrap();
    assert_eq!(undecodable.first_bound(), LifetimeBound::Unknown);
    assert!(!undecodable.holds_at(&KeyPackageInputs::read(&client).unwrap()));
}

/// Stores a copy of alice's `template`, signed with her own key, that is
/// valid for an hour from `not_before`.
fn store_own_bundle_valid_from(app: &MarmotApp, template: &KeyPackage, not_before: u64) {
    use cgka_engine::provider::EngineOpenMlsProvider;
    use cgka_traits::storage::{AccountDeviceSignerStorage as _, StorageProvider as _};
    use openmls::prelude::{
        CredentialWithKey, KeyPackage as MlsKeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn,
        ProtocolVersion,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::Deserialize as _;

    let storage = app.account_storage("alice").unwrap();
    let account = app.account_home().account("alice").unwrap();
    let identity = MemberId::new(hex::decode(account.account_id_hex).unwrap());
    let binding = storage.account_device_signer(&identity).unwrap().unwrap();
    let suite = cgka_engine::DEFAULT_CIPHERSUITE;
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        suite.signature_algorithm(),
    )
    .unwrap();
    let MlsMessageBodyIn::KeyPackage(template) =
        MlsMessageIn::tls_deserialize_exact(template.bytes())
            .unwrap()
            .extract()
    else {
        panic!("expected a KeyPackage")
    };
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let template = template.validate(&crypto, ProtocolVersion::Mls10).unwrap();
    let leaf = template.leaf_node();
    MlsKeyPackage::builder()
        .leaf_node_capabilities(leaf.capabilities().clone())
        .leaf_node_extensions(leaf.extensions().clone())
        .key_package_lifetime(Lifetime::init(not_before, not_before + 3_600))
        .mark_as_last_resort()
        .build(
            suite,
            &EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
                &crypto,
                storage.mls_storage(),
            ),
            &signer,
            CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: signer.public().into(),
            },
        )
        .unwrap();
}

/// The device-group check hides a group when it fails, so the host never
/// learns of a group through a check that failed. That failure can clear with
/// no write, so the entry it hides is not reused: the next publish reads the
/// check again. Here a TEMP table on the app's connection shadows the
/// device-group table, failing the check without writing the database.
#[tokio::test]
async fn a_group_hidden_by_a_failed_device_group_check_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("visible", &[]).await.unwrap();
    let storage = app.account_storage("alice").unwrap().app_storage();
    storage
        .execute_batch_for_test("CREATE TEMP TABLE device_groups (shadow INTEGER)")
        .unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    assert_eq!(state.borrow().host_may_see(&group), Some(false));

    storage
        .execute_batch_for_test("DROP TABLE temp.device_groups")
        .unwrap();
    client.publish_read_state();
    assert_eq!(state.borrow().host_may_see(&group), Some(true));
}

/// A legacy self-update fanout owes its relays only until its bound, so the
/// entry's commit-delivery answer depends on the wall clock. An entry built
/// after the bound passed answers that nothing is owed; moving the clock back
/// before the bound brings it back into force, so the next publish rebuilds
/// the entry instead of reusing it. The answer's window starts at the reading
/// that decided it, so a step back right after that reading counts too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_moved_back_rebuilds_the_time_dependent_entry() {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Reads `0`; after a read, moves to `1` once when it is set.
    struct SetClock(Arc<AtomicU64>, Arc<AtomicU64>);
    impl marmot_session::WallClock for SetClock {
        fn now(&self) -> Timestamp {
            let now = self.0.load(Ordering::SeqCst);
            let step = self.1.swap(0, Ordering::SeqCst);
            if step != 0 {
                self.0.store(step, Ordering::SeqCst);
            }
            Timestamp(now)
        }
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst) * 1_000
        }
    }
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("bounded", &[]).await.unwrap();
    let clock = Arc::new(AtomicU64::new(1_200));
    let step_after_read = Arc::new(AtomicU64::new(0));
    client.runtime = client.runtime.with_maintenance_sources(
        Arc::new(SetClock(Arc::clone(&clock), Arc::clone(&step_after_read))),
        Arc::new(marmot_session::SystemMonotonicClock::default()),
        Arc::new(marmot_session::OsMaintenanceRandom),
    );
    let id = cgka_traits::MessageId::new(vec![0x5e; 32]);
    let endpoint = |url: &str| cgka_traits::TransportEndpoint(url.to_owned());
    let target = |url: &str, state| cgka_traits::TransportFanoutTarget {
        endpoint: endpoint(url),
        state,
        attempt_count: 1,
        last_attempt_at: Some(Timestamp(1_000)),
        failure_code: None,
    };
    client
        .runtime
        .session()
        .put_transport_fanout(&cgka_traits::DurableTransportFanout {
            id: id.clone(),
            group_id: Some(group.clone()),
            evolution_id: Some(id.clone()),
            exact_message: cgka_traits::TransportMessage {
                id: id.clone(),
                payload: vec![0x5e; 16],
                timestamp: Timestamp(1_000),
                causal_deps: Vec::new(),
                source: cgka_traits::TransportSource("nostr".to_owned()),
                envelope: cgka_traits::TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0x42; 32],
                },
            },
            target: cgka_traits::TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id: vec![0x42; 32],
                endpoints: vec![endpoint("wss://a.example"), endpoint("wss://b.example")],
            },
            targets: vec![
                target(
                    "wss://a.example",
                    cgka_traits::TransportFanoutAttemptState::Accepted,
                ),
                target(
                    "wss://b.example",
                    cgka_traits::TransportFanoutAttemptState::AttemptedFailed,
                ),
            ],
            required_acks: 1,
            evolution_confirmed: true,
            possible_exposure: false,
            created_at: Timestamp(1_000),
            bounded_until: Some(Timestamp(1_100)),
        })
        .unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (_, expired) = entry(&state, &group);
    assert_eq!(state.borrow().group_commit_delivery(&group).unwrap(), None);

    clock.store(1_050, Ordering::SeqCst);
    client.publish_read_state();
    let (_, in_force) = entry(&state, &group);
    assert!(!Arc::ptr_eq(&expired, &in_force));
    assert!(
        state
            .borrow()
            .group_commit_delivery(&group)
            .unwrap()
            .is_some()
    );
    // The version carries the bound the owed answer holds until.
    assert_eq!(state.borrow().valid_until, Some(Timestamp(1_100)));

    clock.store(1_200, Ordering::SeqCst);
    step_after_read.store(1_050, Ordering::SeqCst);
    let (owed, window) = client.runtime.undelivered_commit_until(&group).unwrap();
    assert_eq!(owed, None);
    assert_eq!(window.from, Timestamp(1_200));
    assert!(!window.contains(client.runtime.wall_clock_now()));
}

/// A snapshot answers reads while a long unit holds the client, so it never
/// leads A: capturing one publishes what it describes first.
#[tokio::test]
async fn a_snapshot_never_leads_a() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let group = client.create_group("snapshotted", &[]).await.unwrap();
    assert!(!state.borrow().groups.contains_key(&group));

    let snapshot = client.group_read_snapshot().unwrap();
    assert!(snapshot.group_mls_state(&group).is_ok());
    assert!(state.borrow().groups.contains_key(&group));
}
