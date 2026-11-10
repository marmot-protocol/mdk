use super::*;
use marmot_account::Nip46SessionRecord;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_restore_and_signout() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let config = MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let open_app = || {
        MarmotApp::with_relays_and_account_home_and_config(
            dir.path(),
            vec!["wss://account-relay.example".into()],
            home.clone(),
            config.clone(),
        )
        .with_test_relay_client(relay.clone())
    };
    let app = open_app();
    let mut accounts = Vec::new();
    let mut communication_keys = Vec::new();
    for index in 0..2 {
        let user = Keys::generate();
        let account = home
            .add_external_signer_account(&user.public_key().to_hex())
            .unwrap();
        app.register_external_signer(&account.label, TestExternalAccountSigner { keys: user })
            .await
            .unwrap();
        // Persist a genuine MLS identity proof before the remote signer goes offline.
        drop(app.client(&account.label).await.unwrap());
        let client = Keys::generate();
        let mut permissions = Nip46Session::permissions();
        if index == 1 {
            permissions.grants.retain(|grant| grant != "nip44_decrypt");
        }
        home.store_nip46_session(
            &account.label,
            &client,
            &Nip46SessionRecord {
                version: 1,
                user_public_key: account.account_id_hex.clone(),
                remote_signer_public_key: Keys::generate().public_key().to_hex(),
                client_public_key: client.public_key().to_hex(),
                relays: vec!["ws://127.0.0.1:9".into()],
                name: format!("Offline account {index}"),
                permission_version: permissions.version,
                permissions: permissions.grants,
            },
        )
        .unwrap();
        accounts.push(account);
        communication_keys.push(client.public_key());
    }
    app.close_storage().unwrap();
    drop(app);

    let app = open_app();
    let runtime = app.runtime();
    tokio::time::timeout(Duration::from_secs(5), runtime.start())
        .await
        .expect("offline restoration must not await the 90-second signer RPC deadline")
        .unwrap();
    let managed = runtime.accounts().managed_accounts().unwrap();
    for account in &accounts {
        assert!(
            managed
                .iter()
                .any(|entry| entry.account_id_hex == account.account_id_hex && entry.running)
        );
    }
    let restored_a = runtime.nip46_resume(&accounts[0].label).await.unwrap();
    let restored_b = runtime.nip46_resume(&accounts[1].label).await.unwrap();
    assert_eq!(
        restored_a.public_key().unwrap().to_hex(),
        accounts[0].account_id_hex
    );
    assert_eq!(
        restored_b.public_key().unwrap().to_hex(),
        accounts[1].account_id_hex
    );
    assert_ne!(communication_keys[0], communication_keys[1]);
    assert_eq!(restored_b.status().state, Nip46State::PermissionApproval);
    assert_eq!(
        restored_b.connect(),
        Err(Nip46Error::PermissionApprovalRequired)
    );
    let (_, retained) = home
        .load_nip46_session(&accounts[1].label)
        .unwrap()
        .unwrap();
    assert!(
        !retained
            .permissions
            .iter()
            .any(|grant| grant == "nip44_decrypt")
    );
    let approved = restored_b.review_permissions();
    restored_b
        .approve_permissions(approved.version, approved.grants.clone())
        .unwrap();
    let (_, renewed) = home
        .load_nip46_session(&accounts[1].label)
        .unwrap()
        .unwrap();
    assert_eq!(renewed.permissions, approved.grants);
    restored_a.cancel();
    let recovered_a = runtime.nip46_resume(&accounts[0].label).await.unwrap();
    assert_eq!(restored_a.public_key(), Err(Nip46Error::Cancelled));
    assert_eq!(
        recovered_a.public_key().unwrap().to_hex(),
        accounts[0].account_id_hex
    );

    let (_, mut record) = home
        .load_nip46_session(&accounts[0].label)
        .unwrap()
        .unwrap();
    recovered_a.cancel();
    let logging_out = recovered_a.clone();
    assert_eq!(
        tokio::task::spawn_blocking(move || logging_out.logout())
            .await
            .unwrap(),
        Err(Nip46Error::Cancelled)
    );
    assert!(!app.has_external_signer(&accounts[0].account_id_hex));
    assert!(
        home.load_nip46_session(&accounts[0].label)
            .unwrap()
            .is_none()
    );
    runtime.reconcile_accounts().await.unwrap();
    let managed = runtime.accounts().managed_accounts().unwrap();
    assert!(managed.iter().any(
        |account| account.account_id_hex == accounts[0].account_id_hex
            && !account.running
            && !account.signed_out
    ));
    assert!(
        managed
            .iter()
            .any(|account| account.account_id_hex == accounts[1].account_id_hex && account.running)
    );
    let replacement_key = Keys::generate();
    record.client_public_key = replacement_key.public_key().to_hex();
    home.store_nip46_session(&accounts[0].label, &replacement_key, &record)
        .unwrap();
    let replacement = runtime.nip46_resume(&accounts[0].label).await.unwrap();
    recovered_a.erase_local().unwrap();
    assert_eq!(
        home.load_nip46_session(&accounts[0].label)
            .unwrap()
            .unwrap()
            .0
            .public_key(),
        replacement_key.public_key()
    );
    let recovered_a = replacement;

    let outcome = runtime
        .sign_out(
            &accounts[0].label,
            crate::runtime::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(
        outcome.local_cleanup.completed,
        "{:?}",
        outcome.local_cleanup.reason
    );
    assert!(
        home.load_nip46_session(&accounts[0].label)
            .unwrap()
            .is_none()
    );
    assert_eq!(recovered_a.public_key(), Err(Nip46Error::LoggedOut));
    let (remaining_key, _) = home
        .load_nip46_session(&accounts[1].label)
        .unwrap()
        .unwrap();
    assert_eq!(remaining_key.public_key(), communication_keys[1]);
    assert_eq!(
        restored_b.public_key().unwrap().to_hex(),
        accounts[1].account_id_hex
    );
    runtime.shutdown_and_close().await.unwrap();
    assert_eq!(restored_b.public_key(), Err(Nip46Error::Cancelled));
    assert!(
        home.load_nip46_session(&accounts[1].label)
            .unwrap()
            .is_some()
    );
}
