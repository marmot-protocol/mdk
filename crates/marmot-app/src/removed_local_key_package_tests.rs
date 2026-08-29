use super::*;

fn directory_key_package(stable_slot_id: &str, created_at: u64) -> DirectoryKeyPackage {
    DirectoryKeyPackage {
        key_package_id: stable_slot_id.to_owned(),
        key_package_ref_hex: "11".repeat(32),
        key_package_event_id: format!("{created_at:064x}"),
        key_package_hex: "33".repeat(32),
        created_at,
        source_relays: vec!["wss://relay.example".to_owned()],
    }
}

async fn fresh_key_package_for_removed_slot_test(
    app: &MarmotApp,
    account: &AccountSummary,
) -> KeyPackage {
    let signer = app.account_signer_for_summary(account).unwrap();
    let session_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let keys = app
        .account_home()
        .load_signing_keys(&account.label)
        .unwrap();
    let session_key = app
        .sqlcipher_key(
            &account.label,
            &keys,
            session_path.as_ref(),
            SqlcipherDatabaseKind::Session,
        )
        .unwrap();
    let account_id = MemberId::new(hex::decode(&account.account_id_hex).unwrap());
    let config = SessionConfig::new(
        session_path.to_path_buf(),
        session_key,
        account_id.as_slice().to_vec(),
        Box::new(NostrMlsPeeler::new().with_welcome_signer(signer.as_nostr_signer())),
    )
    .account_identity_proof_signer(signer.as_proof_signer())
    .feature_registry(app_feature_registry())
    .supported_app_components(app.supported_app_component_ids());
    AccountDeviceSession::open(config)
        .unwrap()
        .fresh_key_package()
        .await
        .unwrap()
}

fn key_package_event_for_removed_slot_test(
    account: &AccountSummary,
    key_package: KeyPackage,
    stable_slot_id: &str,
) -> NostrTransportEvent {
    let metadata = cgka_engine::key_package::key_package_metadata(&key_package).unwrap();
    transport_nostr_adapter::NostrKeyPackagePublication {
        account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
        key_package,
        key_package_slot_id: stable_slot_id.to_owned(),
        key_package_ref: metadata.key_package_ref_hex,
        mls_ciphersuite: format!("0x{:04x}", metadata.ciphersuite),
        mls_extensions: metadata
            .mls_extensions
            .iter()
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        mls_proposals: metadata
            .mls_proposals
            .iter()
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        app_components: metadata
            .app_components
            .iter()
            .filter(|id| **id >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START)
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        publish_endpoints: vec![TransportEndpoint("wss://relay.example".to_owned())],
    }
    .to_event()
    .unwrap()
}

#[test]
fn exact_removed_local_slot_is_durable_and_scrubs_every_projection() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let removed = home.create_account("removed").unwrap();
    let viewer = home.create_account("viewer").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_storage(&removed.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "removed-slot".to_owned(),
        ))
        .unwrap();

    let mut entry = app.empty_directory_record(&removed.account_id_hex);
    entry.profile = Some(UserProfileMetadata {
        name: Some("still-public".to_owned()),
        created_at: 10,
        ..UserProfileMetadata::default()
    });
    entry.follows = vec![viewer.account_id_hex.clone()];
    entry.key_package = Some(directory_key_package("removed-slot", 20));
    app.save_directory_entry(&entry).unwrap();
    let viewer_cache = app
        .directory_cache_for_account(&app.account_home().account(&viewer.label).unwrap())
        .unwrap();
    assert_eq!(
        viewer_cache
            .entry(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .unwrap()
            .key_package_id,
        "removed-slot"
    );

    app.persist_removed_local_key_package_tombstone(&removed)
        .unwrap();
    assert!(
        app.removed_local_key_package_slot_is_retired(&removed.account_id_hex, "removed-slot")
            .unwrap()
    );
    assert!(
        !app.removed_local_key_package_slot_is_retired(&removed.account_id_hex, "sibling-slot")
            .unwrap()
    );
    let shared = app
        .shared_storage()
        .unwrap()
        .public_directory_user(&removed.account_id_hex)
        .unwrap()
        .unwrap();
    assert!(shared.key_package_json.is_none());
    assert_eq!(
        shared
            .profile_json
            .as_deref()
            .map(serde_json::from_str::<UserProfileMetadata>)
            .transpose()
            .unwrap()
            .and_then(|profile| profile.name),
        Some("still-public".to_owned())
    );
    let cached = viewer_cache
        .entry(&removed.account_id_hex)
        .unwrap()
        .unwrap();
    assert!(cached.key_package.is_none());
    assert_eq!(cached.follows, vec![viewer.account_id_hex.clone()]);

    // A delayed echo or an unrelated profile update carrying the stale whole
    // record cannot copy the removed slot back into either projection.
    app.save_directory_entry(&entry).unwrap();
    assert!(
        app.shared_storage()
            .unwrap()
            .public_directory_user(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package_json
            .is_none()
    );
    assert!(
        viewer_cache
            .entry(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .is_none()
    );

    let marker = app
        .removed_local_key_package_account_tombstone_dir(&removed.account_id_hex)
        .unwrap()
        .join("slots.json");
    assert!(marker.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(marker.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    app.drop_account_caches(&removed.label);
    app.account_home().remove_account(&removed.label).unwrap();
    let mut sibling = app.empty_directory_record(&removed.account_id_hex);
    sibling.key_package = Some(directory_key_package("sibling-slot", 30));
    app.save_directory_entry(&sibling).unwrap();
    assert_eq!(
        app.directory_entry_for_account_id(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .unwrap()
            .key_package_id,
        "sibling-slot",
        "retiring one local device slot must preserve a sibling device"
    );

    // A stale read-modify-write can carry the removed slot alongside a newer
    // independent profile coordinate. Filtering that slot must not let the
    // profile timestamp erase the already cached sibling-device package.
    let mut stale_profile_update = entry.clone();
    stale_profile_update.profile.as_mut().unwrap().created_at = 40;
    app.save_directory_entry(&stale_profile_update).unwrap();
    let merged = app
        .directory_entry_for_account_id(&removed.account_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(merged.profile.unwrap().created_at, 40);
    assert_eq!(
        merged.key_package.unwrap().key_package_id,
        "sibling-slot",
        "an independent profile update must not erase a live sibling slot"
    );

    drop(viewer_cache);
    drop(app);
    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    assert!(
        reopened
            .removed_local_key_package_slot_is_retired(&removed.account_id_hex, "removed-slot")
            .unwrap(),
        "the removal authority must survive a process restart"
    );
    assert_eq!(
        reopened
            .directory_entry_for_account_id(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .unwrap()
            .key_package_id,
        "sibling-slot"
    );
}

#[tokio::test]
async fn account_manager_commits_slot_tombstone_before_account_home_removal() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("removed-by-manager")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "manager-slot".to_owned(),
        ))
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());

    runtime
        .accounts()
        .remove_account(&account.label)
        .await
        .unwrap();

    assert!(matches!(
        app.account_home().account(&account.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "manager-slot")
            .unwrap()
    );
    assert!(
        app.removed_local_key_package_account_tombstone_dir(&account.account_id_hex)
            .unwrap()
            .join("slots.json")
            .exists()
    );
    runtime.shutdown().await;
}

#[test]
fn directory_warm_retries_a_post_tombstone_projection_scrub() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let removed = home.create_account("crash-window-removed").unwrap();
    let viewer = home.create_account("crash-window-viewer").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_storage(&removed.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "crash-window-slot".to_owned(),
        ))
        .unwrap();
    let mut stale = app.empty_directory_record(&removed.account_id_hex);
    stale.key_package = Some(directory_key_package("crash-window-slot", 20));
    app.save_directory_entry(&stale).unwrap();
    app.persist_removed_local_key_package_tombstone(&removed)
        .unwrap();

    // Model a process dying after the atomic marker rename but before its
    // best-effort scrub. These direct storage calls intentionally bypass the
    // production admission gate to reconstruct that crash residue.
    app.shared_storage()
        .unwrap()
        .put_public_directory_user(
            &crate::directory::records::public_directory_user_record(&stale).unwrap(),
        )
        .unwrap();
    let viewer_cache = app
        .directory_cache_for_account(&app.account_home().account(&viewer.label).unwrap())
        .unwrap();
    viewer_cache.put(&stale).unwrap();
    drop(viewer_cache);
    drop(app);

    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    reopened.warm_directory_storage().unwrap();
    assert!(
        reopened
            .shared_storage()
            .unwrap()
            .public_directory_user(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package_json
            .is_none()
    );
    let viewer_cache = reopened
        .directory_cache_for_account(&reopened.account_home().account(&viewer.label).unwrap())
        .unwrap();
    assert!(
        viewer_cache
            .entry(&removed.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .is_none()
    );
}

#[test]
fn account_wide_legacy_fallback_allows_only_a_new_active_lifecycle_slot() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("legacy")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    // No lifecycle and no compatibility record means the old slot is
    // unprovable; removal must record the explicit account-wide fallback.
    app.persist_removed_local_key_package_tombstone(&account)
        .unwrap();
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "unknown-old-slot")
            .unwrap()
    );

    let key_package_ref = vec![0x11; 32];
    let event_id = cgka_traits::MessageId::new(vec![0x22; 32]);
    let mut lifecycle =
        cgka_traits::KeyPackageLifecycleState::slot_only("fresh-reimport-slot".to_owned());
    lifecycle.current_key_package_ref = Some(key_package_ref.clone());
    lifecycle.authored_event_id = Some(event_id.clone());
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    assert!(
        !app.removed_local_key_package_slot_is_retired(
            &account.account_id_hex,
            "fresh-reimport-slot"
        )
        .unwrap()
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "unknown-old-slot")
            .unwrap()
    );

    // Relay admission already owns the non-reentrant session mutex. The
    // account-wide fallback must consume that proof through hydration and the
    // cache-write boundary instead of trying to lock the mutex a second time.
    let fetched = FetchedKeyPackage {
        account_id_hex: account.account_id_hex.clone(),
        key_package: KeyPackage::new(vec![0x33; 32]),
        key_package_id: "fresh-reimport-slot".to_owned(),
        key_package_ref_hex: hex::encode(key_package_ref),
        key_package_event_id: hex::encode(event_id.as_slice()),
        created_at: 30,
        source_relays: vec!["wss://relay.example".to_owned()],
        relay_lists: AccountRelayListStatus::empty(),
    };
    let worker_app = app.clone();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = worker_app.remember_directory_key_package_if_live(&fetched);
        let _ = finished_tx.send(result);
    });
    assert!(
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("legacy re-import KeyPackage admission must not deadlock")
            .unwrap()
    );
    worker.join().unwrap();
    assert_eq!(
        app.directory_entry_for_account_id(&account.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .unwrap()
            .key_package_id,
        "fresh-reimport-slot"
    );
}

#[tokio::test]
async fn mismatched_legacy_key_package_cannot_choose_an_exact_removed_slot() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let removed = home.create_account("legacy-removed").unwrap();
    let other = home.create_account("legacy-other").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let other_key_package = fresh_key_package_for_removed_slot_test(&app, &other).await;
    let claimed_slot = "untrusted-legacy-slot";
    write_json(
        app.key_package_record_path(&removed.label),
        &KeyPackageRecord {
            account_label: removed.label.clone(),
            account_id_hex: removed.account_id_hex.clone(),
            key_package_id: claimed_slot.to_owned(),
            key_package_ref_hex: String::new(),
            key_package_event_id: String::new(),
            published_at: 1,
            key_package_hex: hex::encode(other_key_package.bytes()),
        },
    )
    .unwrap();

    app.persist_removed_local_key_package_tombstone(&removed)
        .unwrap();

    assert!(
        app.removed_local_key_package_account_tombstone_dir(&removed.account_id_hex)
            .unwrap()
            .join("slots.json")
            .exists(),
        "an unverifiable compatibility record must fall back to account-wide retirement"
    );
    let exact_marker = app
        .removed_local_key_package_tombstone_path(&removed.account_id_hex, Some(claimed_slot))
        .unwrap();
    assert!(
        !exact_marker.exists(),
        "a mismatched credential must not authorize an exact-slot tombstone"
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&removed.account_id_hex, claimed_slot)
            .unwrap()
    );
}

#[tokio::test]
async fn account_wide_legacy_fallback_does_not_deadlock_live_relay_ingest() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("legacy-ingest")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.persist_removed_local_key_package_tombstone(&account)
        .unwrap();

    let stable_slot_id = "fresh-ingest-slot";
    let key_package = fresh_key_package_for_removed_slot_test(&app, &account).await;
    let metadata = cgka_engine::key_package::key_package_metadata(&key_package).unwrap();
    let event =
        key_package_event_for_removed_slot_test(&account, key_package.clone(), stable_slot_id);
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only(stable_slot_id.to_owned());
    lifecycle.current_key_package = Some(key_package);
    lifecycle.current_key_package_ref = Some(hex::decode(&metadata.key_package_ref_hex).unwrap());
    lifecycle.authored_event_id =
        Some(cgka_traits::MessageId::new(hex::decode(&event.id).unwrap()));
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    let record = crate::relay_plane::DirectoryRelayEventRecord {
        endpoints: vec![TransportEndpoint("wss://relay.example".to_owned())],
        event,
    };
    let worker_app = app.clone();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = worker_app.ingest_directory_relay_event(record);
        let _ = finished_tx.send(result);
    });
    finished_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("legacy re-import relay ingestion must not deadlock")
        .unwrap();
    worker.join().unwrap();
    assert_eq!(
        app.directory_entry_for_account_id(&account.account_id_hex)
            .unwrap()
            .unwrap()
            .key_package
            .unwrap()
            .key_package_id,
        stable_slot_id
    );
}

#[test]
fn tombstone_persistence_failure_leaves_account_bytes_intact() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("failure")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "slot".to_owned(),
        ))
        .unwrap();

    let tombstone_root = app.removed_local_key_package_tombstone_root();
    std::fs::create_dir_all(tombstone_root.parent().unwrap()).unwrap();
    std::fs::write(&tombstone_root, b"path collision").unwrap();

    assert!(
        app.persist_removed_local_key_package_tombstone(&account)
            .is_err()
    );
    assert!(app.account_home().account(&account.label).is_ok());
    assert!(app.account_storage_path(&account.label).exists());
    assert!(app.account_home().load_signing_keys(&account.label).is_ok());
}

#[test]
fn distinct_slot_tombstones_keep_exact_retired_slot_proof() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("coalesce-slots")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "first-slot".to_owned(),
        ))
        .unwrap();
    app.persist_removed_local_key_package_tombstone(&account)
        .unwrap();
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "first-slot")
            .unwrap()
    );

    let second = app
        .removed_local_key_package_tombstone_path(&account.account_id_hex, Some("second-slot"))
        .unwrap();
    write_json(
        &second,
        &serde_json::json!({
            "account_id_hex": account.account_id_hex,
            "stable_slot_id": "second-slot",
        }),
    )
    .unwrap();
    app.persist_removed_local_key_package_tombstone(&account)
        .unwrap();

    let account_wide = app
        .removed_local_key_package_tombstone_path(&account.account_id_hex, None)
        .unwrap();
    assert!(
        !account_wide.exists(),
        "a second exact slot must not collapse retired-slot proof into all.json"
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "first-slot")
            .unwrap()
            && app
                .removed_local_key_package_slot_is_retired(&account.account_id_hex, "second-slot")
                .unwrap(),
        "exact retired-slot identities must survive compaction into the bounded journal"
    );
    let tombstone_dir = app
        .removed_local_key_package_account_tombstone_dir(&account.account_id_hex)
        .unwrap();
    let leftover = std::fs::read_dir(&tombstone_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        leftover.len(),
        1,
        "compaction must leave one journal file, got {leftover:?}"
    );

    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "first-slot".to_owned(),
        ))
        .unwrap();
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "first-slot")
            .unwrap(),
        "re-admitting a retired lifecycle must not resurrect it without an exact marker"
    );
}

#[test]
fn removed_local_key_package_tombstone_journal_fails_closed_at_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("tombstone-cap")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let journal_dir = app
        .removed_local_key_package_account_tombstone_dir(&account.account_id_hex)
        .unwrap();
    std::fs::create_dir_all(&journal_dir).unwrap();
    let retired = (0..256)
        .map(|index| format!("filled-slot-{index}"))
        .collect::<Vec<_>>();
    write_json(
        journal_dir.join("slots.json"),
        &serde_json::json!({
            "account_id_hex": account.account_id_hex,
            "retired_stable_slot_ids": retired,
            "account_wide": false,
        }),
    )
    .unwrap();
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "overflow-slot".to_owned(),
        ))
        .unwrap();
    assert!(
        app.persist_removed_local_key_package_tombstone(&account)
            .is_err(),
        "a 257th distinct retired slot must fail closed"
    );
    assert!(
        !app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "overflow-slot")
            .unwrap(),
        "a rejected overflow slot must not be recorded as retired"
    );
}

#[test]
fn oversized_tombstone_journal_fails_closed_without_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("tombstone-oversized")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let journal_dir = app
        .removed_local_key_package_account_tombstone_dir(&account.account_id_hex)
        .unwrap();
    std::fs::create_dir_all(&journal_dir).unwrap();
    let retired = (0..257)
        .map(|index| format!("oversized-slot-{index}"))
        .collect::<Vec<_>>();
    write_json(
        journal_dir.join("slots.json"),
        &serde_json::json!({
            "account_id_hex": account.account_id_hex,
            "retired_stable_slot_ids": retired,
            "account_wide": false,
        }),
    )
    .unwrap();
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "fresh-slot".to_owned(),
        ))
        .unwrap();
    assert!(
        app.persist_removed_local_key_package_tombstone(&account)
            .is_err(),
        "an oversized slots.json must fail closed before write or cleanup"
    );
    let loaded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal_dir.join("slots.json")).unwrap()).unwrap();
    assert_eq!(
        loaded["retired_stable_slot_ids"].as_array().map(Vec::len),
        Some(257),
        "rejection must preserve the oversized journal"
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "oversized-slot-0")
            .is_err(),
        "an oversized journal must not be treated as a successful retirement read"
    );
}

#[test]
fn partial_or_typoed_tombstone_journal_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("tombstone-partial")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let journal_path = app
        .removed_local_key_package_tombstone_journal_path(&account.account_id_hex)
        .unwrap();
    std::fs::create_dir_all(journal_path.parent().unwrap()).unwrap();
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "fresh-slot".to_owned(),
        ))
        .unwrap();

    let cases = [
        (
            "account-id only",
            serde_json::json!({
                "account_id_hex": account.account_id_hex,
            }),
        ),
        (
            "missing retired slots",
            serde_json::json!({
                "account_id_hex": account.account_id_hex,
                "account_wide": false,
            }),
        ),
        (
            "missing account-wide proof",
            serde_json::json!({
                "account_id_hex": account.account_id_hex,
                "retired_stable_slot_ids": ["retired-slot"],
            }),
        ),
        (
            "typoed proof field",
            serde_json::json!({
                "account_id_hex": account.account_id_hex,
                "retired_stable_slot_id": ["retired-slot"],
                "account_wide": false,
            }),
        ),
    ];

    for (label, value) in cases {
        write_json(&journal_path, &value).unwrap();
        let before = std::fs::read(&journal_path).unwrap();
        assert!(
            app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "retired-slot",)
                .is_err(),
            "{label} must not deserialize as an empty retirement proof"
        );
        assert!(
            app.persist_removed_local_key_package_tombstone(&account)
                .is_err(),
            "{label} must abort removal before rewriting tombstone state"
        );
        assert_eq!(
            std::fs::read(&journal_path).unwrap(),
            before,
            "{label} must remain untouched for explicit recovery"
        );
    }
}

#[test]
fn malformed_legacy_exact_slot_tombstone_is_not_deleted_on_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("tombstone-malformed")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let journal_dir = app
        .removed_local_key_package_account_tombstone_dir(&account.account_id_hex)
        .unwrap();
    std::fs::create_dir_all(&journal_dir).unwrap();
    let none_path = app
        .removed_local_key_package_tombstone_path(&account.account_id_hex, Some("slot-a"))
        .unwrap();
    write_json(
        &none_path,
        &serde_json::json!({
            "account_id_hex": account.account_id_hex,
            "stable_slot_id": serde_json::Value::Null,
        }),
    )
    .unwrap();
    let mismatched_path = app
        .removed_local_key_package_tombstone_path(&account.account_id_hex, Some("slot-c"))
        .unwrap();
    write_json(
        &mismatched_path,
        &RemovedLocalKeyPackageTombstone {
            account_id_hex: account.account_id_hex.clone(),
            stable_slot_id: Some("slot-b".to_owned()),
        },
    )
    .unwrap();
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "sibling-slot".to_owned(),
        ))
        .unwrap();
    app.persist_removed_local_key_package_tombstone(&account)
        .unwrap();

    assert!(
        none_path.exists(),
        "a None payload on slot-A's filename must survive compaction"
    );
    assert!(
        mismatched_path.exists(),
        "a slot-C file carrying slot-B must survive compaction"
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "sibling-slot")
            .unwrap()
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "slot-a")
            .is_err(),
        "the remaining None marker must keep slot-A fail-closed"
    );
    assert!(
        app.removed_local_key_package_slot_is_retired(&account.account_id_hex, "slot-c")
            .is_err(),
        "the remaining mismatched marker must keep slot-C fail-closed"
    );
    let journal: RemovedLocalKeyPackageTombstoneJournal = read_json(
        app.removed_local_key_package_tombstone_journal_path(&account.account_id_hex)
            .unwrap(),
    )
    .unwrap();
    assert!(
        !journal
            .retired_stable_slot_ids
            .iter()
            .any(|slot| slot == "slot-a" || slot == "slot-c" || slot == "slot-b"),
        "malformed legacy markers must not be imported as retired identities"
    );
}

#[test]
fn merged_legacy_tombstones_fail_closed_before_exceeding_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("tombstone-merged-cap")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let journal_dir = app
        .removed_local_key_package_account_tombstone_dir(&account.account_id_hex)
        .unwrap();
    std::fs::create_dir_all(&journal_dir).unwrap();
    let retired = (0..256)
        .map(|index| format!("filled-slot-{index}"))
        .collect::<Vec<_>>();
    write_json(
        journal_dir.join("slots.json"),
        &serde_json::json!({
            "account_id_hex": account.account_id_hex,
            "retired_stable_slot_ids": retired,
            "account_wide": false,
        }),
    )
    .unwrap();
    let extra_path = app
        .removed_local_key_package_tombstone_path(
            &account.account_id_hex,
            Some("imported-overflow"),
        )
        .unwrap();
    write_json(
        &extra_path,
        &RemovedLocalKeyPackageTombstone {
            account_id_hex: account.account_id_hex.clone(),
            stable_slot_id: Some("imported-overflow".to_owned()),
        },
    )
    .unwrap();
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "fresh-slot".to_owned(),
        ))
        .unwrap();
    assert!(
        app.persist_removed_local_key_package_tombstone(&account)
            .is_err(),
        "importing a 257th legacy slot must fail before write or cleanup"
    );
    assert!(
        extra_path.exists(),
        "capacity rejection must preserve the unimported legacy proof"
    );
}

#[test]
fn tracked_only_removal_does_not_create_local_slot_authority() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let tracked = home
        .add_public_account(&nostr_sdk::prelude::Keys::generate().public_key().to_hex())
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    app.persist_removed_local_key_package_tombstone(&tracked)
        .unwrap();
    assert!(
        !app.removed_local_key_package_slot_is_retired(&tracked.account_id_hex, "remote-slot")
            .unwrap()
    );
    assert!(
        !app.removed_local_key_package_account_tombstone_dir(&tracked.account_id_hex)
            .unwrap()
            .exists()
    );
}
