use super::*;
use std::sync::{Arc, Barrier};

#[test]
fn salt_publication_never_replaces_existing_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.sqlite.salt");
    write_sqlcipher_salt(&path, &[1; SQLCIPHER_SALT_LEN]).unwrap();
    let second = write_sqlcipher_salt(&path, &[2; SQLCIPHER_SALT_LEN]);
    assert!(
        matches!(second, Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(read_sqlcipher_salt(&path).unwrap(), [1; SQLCIPHER_SALT_LEN]);
}

#[test]
fn concurrent_first_account_opens_preserve_reopenability() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_home().create_account("new").unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let results = std::thread::scope(|scope| {
        let tasks = (0..8)
            .map(|_| {
                let app = &app;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    app.account_storage("new")
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    for result in results {
        result.expect("all concurrent first opens must succeed");
    }
    let path = app.account_storage_path("new");
    let salt = fs::read(sqlcipher_salt_path(&path)).unwrap();
    app.close_storage().unwrap();
    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    reopened
        .account_storage("new")
        .expect("persisted salt must still open the database");
    assert_eq!(fs::read(sqlcipher_salt_path(&path)).unwrap(), salt);
}

#[tokio::test]
async fn generated_account_attention_waits_for_local_readiness() {
    use crate::{AccountAttentionState, AccountAttentionUnavailable, MarmotAppRuntime};
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account = app.account_home().create_nostr_account_for_setup().unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let attention = runtime.subscribe_account_attention().await.unwrap();
    assert_eq!(attention.snapshot.accounts.len(), 1);
    assert_eq!(
        attention.snapshot.accounts[0].state,
        AccountAttentionState::Unavailable(AccountAttentionUnavailable::Preparing)
    );
    assert!(!app.account_storage_path(&account.label).exists());
    drop(attention);
    runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn concurrent_first_directory_opens_share_one_handle() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account = app.account_home().create_account("new").unwrap();
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        let tasks = (0..8)
            .map(|_| {
                let (app, account, barrier) = (&app, &account, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    app.directory_cache_for_account(account)
                })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            task.join().unwrap().unwrap();
        }
    });
    assert_eq!(app.directory_cache_open_count.load(Ordering::SeqCst), 1);
    app.close_storage().unwrap();
    let fresh = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    fresh.directory_cache_for_account(&account).unwrap();
}

#[test]
fn concurrent_private_publication_exposes_only_complete_winning_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("salt");
    let barrier = Barrier::new(8);
    let results = std::thread::scope(|scope| {
        let tasks = (1..=8u8)
            .map(|byte| {
                let (path, barrier) = (&path, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    let result = write_sqlcipher_salt(path, &[byte; SQLCIPHER_SALT_LEN]);
                    // A losing publisher may immediately consume the winner.
                    let salt = read_sqlcipher_salt(path).unwrap();
                    (byte, result, salt)
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    let winners = results
        .iter()
        .filter(|(_, result, _)| result.is_ok())
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    let winning_byte = winners[0].0;
    for (_, result, salt) in results {
        if let Err(error) = result {
            assert!(
                matches!(error, AppError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists)
            );
        }
        assert_eq!(salt, [winning_byte; SQLCIPHER_SALT_LEN]);
    }
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        1,
        "no temporary residue"
    );
}

#[test]
fn database_lock_is_stable_across_file_creation_and_parent_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.sqlite");
    let before = database_open_lock(&path);
    fs::write(&path, []).unwrap();
    let after = database_open_lock(&path);
    assert!(Arc::ptr_eq(&before, &after));
    #[cfg(unix)]
    {
        let alias_dir = tempfile::tempdir().unwrap();
        let alias = alias_dir.path().join("alias");
        std::os::unix::fs::symlink(dir.path(), &alias).unwrap();
        assert!(Arc::ptr_eq(
            &before,
            &database_open_lock(&alias.join("session.sqlite"))
        ));
    }
    let different = database_open_lock(&dir.path().join("other.sqlite"));
    let _first = before.lock();
    let _second = different.lock();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_with_live_attention_survives_full_runtime_restart() {
    use crate::{AccountSetupReadiness, AccountSetupRequest, MarmotAppRuntime};
    use cgka_traits::TransportEndpoint;
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let make_app = || {
        MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()))
    };
    let app = make_app();
    let runtime = MarmotAppRuntime::new(app.clone());
    let request = || AccountSetupRequest {
        default_relays: vec![TransportEndpoint("wss://relay.example".into())],
        bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
        ..AccountSetupRequest::default()
    };
    let first = runtime.create_identity(request()).await.unwrap().account;
    let mut accounts = vec![first];
    let attention = runtime.subscribe_account_attention().await.unwrap();
    for _ in 0..3 {
        let created = runtime
            .create_identity_local_ready(request())
            .await
            .unwrap();
        assert!(!accounts.iter().any(|a| a.label == created.account.label));
        tokio::time::timeout(Duration::from_secs(10), async {
            while runtime
                .account_setup_readiness(&created.account.label)
                .unwrap()
                != AccountSetupReadiness::NetworkReady
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        accounts.push(created.account);
    }
    let salts = accounts
        .iter()
        .map(|a| fs::read(sqlcipher_salt_path(&app.account_storage_path(&a.label))).unwrap())
        .collect::<Vec<_>>();
    drop(attention);
    runtime.shutdown_and_close().await.unwrap();
    let fresh = make_app();
    let restarted = MarmotAppRuntime::new(fresh.clone());
    restarted.start().await.unwrap();
    assert_eq!(
        restarted
            .accounts()
            .managed_accounts()
            .unwrap()
            .iter()
            .filter(|a| a.running)
            .count(),
        accounts.len()
    );
    for (account, salt) in accounts.iter().zip(salts) {
        fresh.account_storage(&account.label).unwrap();
        assert_eq!(
            fs::read(sqlcipher_salt_path(
                &fresh.account_storage_path(&account.label)
            ))
            .unwrap(),
            salt
        );
    }
    restarted.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreadable_unfinished_account_is_preserved_while_healthy_account_starts() {
    use crate::{AccountSetupRequest, MarmotAppRuntime};
    use cgka_traits::TransportEndpoint;
    let dir = tempfile::tempdir().unwrap();
    let make_app = || {
        MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()))
    };
    let app = make_app();
    let runtime = MarmotAppRuntime::new(app.clone());
    let original = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap()
        .account;
    let unfinished = app.account_home().create_nostr_account_for_setup().unwrap();
    app.account_storage(&unfinished.label).unwrap();
    app.account_home()
        .set_account_setup_context(
            &unfinished.label,
            &serde_json::to_vec(&serde_json::json!({
                "default_relays": ["wss://relay.example"],
                "bootstrap_relays": ["wss://relay.example"],
                "discovery_relays": [],
                "publish_missing_relay_lists": true,
                "publish_initial_key_package": true
            }))
            .unwrap(),
        )
        .unwrap();
    runtime.shutdown_and_close().await.unwrap();
    let path = app.account_storage_path(&unfinished.label);
    let salt_path = sqlcipher_salt_path(&path);
    // Simulate the historical lost-salt failure; retain a real encrypted DB.
    fs::write(&salt_path, hex::encode([0x42; SQLCIPHER_SALT_LEN])).unwrap();
    let bytes = fs::read(&path).unwrap();
    let salt = fs::read(&salt_path).unwrap();
    let setup = app
        .account_home()
        .account_setup_state(&unfinished.label)
        .unwrap()
        .unwrap();
    let fresh = make_app();
    let restart = MarmotAppRuntime::new(fresh.clone());
    restart.start().await.unwrap();
    let accounts = restart.accounts().managed_accounts().unwrap();
    assert!(
        accounts
            .iter()
            .any(|a| a.label == original.label && a.running)
    );
    assert!(
        accounts
            .iter()
            .any(|a| a.label == unfinished.label && !a.running)
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "unreadable database must not be deleted or changed"
    );
    assert_eq!(fs::read(&salt_path).unwrap(), salt);
    assert_eq!(
        fresh
            .account_home()
            .account_setup_state(&unfinished.label)
            .unwrap()
            .unwrap()
            .phase,
        setup.phase
    );
    fresh
        .account_home()
        .load_signing_keys(&unfinished.label)
        .unwrap();
    restart.shutdown_and_close().await.unwrap();
}
