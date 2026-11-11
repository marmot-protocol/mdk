use super::*;
use ::nostr::prelude::{Event, Filter, PublicKey, nip44};
use ::nostr_sdk::prelude::{Client, ClientNotification};
use futures::StreamExt;
use marmot_account::Nip46SessionRecord;
use marmot_account::{AccountHomeResult, AccountSecretStore, LocalFileSecretStore};

const KEY_PACKAGE_KIND: u64 = 30443;

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

struct LoginPeer {
    relay: nostr_relay_builder::LocalRelay,
    client: Client,
    task: Option<tokio::task::JoinHandle<()>>,
    url: String,
    user: Keys,
    remote: Keys,
    completion_fault: Arc<std::sync::Mutex<Option<AccountHome>>>,
    hold_kp: Arc<std::sync::atomic::AtomicBool>,
    kp_seen: Arc<tokio::sync::Notify>,
    kp_release: Arc<tokio::sync::Notify>,
    signed_profiles: Arc<std::sync::Mutex<Vec<::nostr::prelude::EventId>>>,
}

impl LoginPeer {
    async fn new() -> Self {
        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let client = transport_nostr_adapter::network_proxy::nostr_builder(Ok(None)).build();
        let mut notifications = client.notifications();
        client.add_relay(url.as_str()).await.unwrap();
        client.connect().and_wait(Duration::from_secs(5)).await;
        let remote = Keys::generate();
        let user = Keys::generate();
        client
            .subscribe(
                Filter::new()
                    .kind(Kind::NostrConnect)
                    .pubkey(remote.public_key()),
            )
            .await
            .unwrap();
        let completion_fault = Arc::new(std::sync::Mutex::new(None::<AccountHome>));
        let hold_kp = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kp_seen = Arc::new(tokio::sync::Notify::new());
        let kp_release = Arc::new(tokio::sync::Notify::new());
        let signed_profiles = Arc::new(std::sync::Mutex::new(Vec::new()));
        let task = {
            let client = client.clone();
            let remote = remote.clone();
            let user = user.clone();
            let url = url.clone();
            let completion_fault = completion_fault.clone();
            let hold_kp = hold_kp.clone();
            let kp_seen = kp_seen.clone();
            let kp_release = kp_release.clone();
            let signed_profiles = signed_profiles.clone();
            tokio::spawn(async move {
                let mut seen = std::collections::HashSet::new();
                while let Some(notification) = notifications.next().await {
                    let ClientNotification::Event { event, .. } = notification else {
                        continue;
                    };
                    if !seen.insert(event.id) {
                        continue;
                    }
                    let plaintext =
                        nip44::decrypt(remote.secret_key(), &event.pubkey, &event.content).unwrap();
                    let request: serde_json::Value = serde_json::from_str(&plaintext).unwrap();
                    let params = request["params"].as_array().unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "connect" | "logout" => serde_json::json!("ack"),
                        "ping" => serde_json::json!("pong"),
                        "get_public_key" => serde_json::json!(user.public_key().to_hex()),
                        "switch_relays" => serde_json::json!(serde_json::json!([url]).to_string()),
                        "sign_event" => {
                            let unsigned: serde_json::Value =
                                serde_json::from_str(params[0].as_str().unwrap()).unwrap();
                            if unsigned["kind"].as_u64() == Some(KEY_PACKAGE_KIND)
                                && let Some(home) = completion_fault.lock().unwrap().take()
                            {
                                let account = home.account(&user.public_key().to_hex()).unwrap();
                                std::fs::create_dir(
                                    home.account_dir(&account.label)
                                        .join(".account-setup-context.json"),
                                )
                                .unwrap();
                            }
                            let signed = EventBuilder::new(
                                serde_json::from_value::<Kind>(unsigned["kind"].clone()).unwrap(),
                                unsigned["content"].as_str().unwrap(),
                            )
                            .tags(
                                serde_json::from_value::<::nostr::prelude::Tags>(
                                    unsigned["tags"].clone(),
                                )
                                .unwrap(),
                            )
                            .custom_created_at(
                                serde_json::from_value::<::nostr::prelude::Timestamp>(
                                    unsigned["created_at"].clone(),
                                )
                                .unwrap(),
                            )
                            .finalize(&user)
                            .unwrap();
                            if signed.kind == Kind::Metadata {
                                signed_profiles.lock().unwrap().push(signed.id);
                            }
                            if unsigned["kind"].as_u64() == Some(KEY_PACKAGE_KIND)
                                && hold_kp.swap(false, std::sync::atomic::Ordering::SeqCst)
                            {
                                kp_seen.notify_one();
                                kp_release.notified().await;
                            }
                            serde_json::json!(signed.as_json())
                        }
                        "nip44_encrypt" => serde_json::json!(
                            nip44::encrypt(
                                user.secret_key(),
                                &PublicKey::from_hex(params[0].as_str().unwrap()).unwrap(),
                                params[1].as_str().unwrap(),
                                nip44::Version::V2
                            )
                            .unwrap()
                        ),
                        "nip44_decrypt" => serde_json::json!(
                            nip44::decrypt(
                                user.secret_key(),
                                &PublicKey::from_hex(params[0].as_str().unwrap()).unwrap(),
                                params[1].as_str().unwrap()
                            )
                            .unwrap()
                        ),
                        method => panic!("unexpected signer fixture method: {method}"),
                    };
                    let response = serde_json::json!({"id":request["id"],"result":result});
                    let content = nip44::encrypt(
                        remote.secret_key(),
                        &event.pubkey,
                        response.to_string(),
                        nip44::Version::V2,
                    )
                    .unwrap();
                    let reply = EventBuilder::new(Kind::NostrConnect, content)
                        .tag(Tag::public_key(event.pubkey))
                        .finalize(&remote)
                        .unwrap();
                    client.send_event(&reply).await.unwrap();
                }
            })
        };
        Self {
            relay,
            client,
            task: Some(task),
            url,
            user,
            remote,
            completion_fault,
            hold_kp,
            kp_seen,
            kp_release,
            signed_profiles,
        }
    }

    fn session(&self, app: &MarmotApp) -> Nip46Session {
        let mut uri = url::Url::parse(&format!("bunker://{}", self.remote.public_key())).unwrap();
        uri.query_pairs_mut()
            .append_pair("relay", &self.url)
            .append_pair("secret", "lifecycle-fixture");
        let session =
            Nip46Session::new(app, &serde_json::json!({"uri":uri.as_str()}).to_string()).unwrap();
        let grants = session.review_permissions();
        session
            .approve_permissions(grants.version, grants.grants)
            .unwrap();
        session
    }

    async fn close(mut self) {
        self.kp_release.notify_one();
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.client.disconnect().await;
        self.relay.shutdown();
    }
}

impl Drop for LoginPeer {
    fn drop(&mut self) {
        self.kp_release.notify_one();
        if let Some(task) = &self.task {
            task.abort();
        }
        self.relay.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_drop_restores_host() {
    run_nip46_drop(DropSettlement::Rejection).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_drop_shutdown_settles() {
    run_nip46_drop(DropSettlement::Shutdown).await;
}

enum DropSettlement {
    Rejection,
    Shutdown,
    NewSignIn,
    LocalRemove,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_drop_remove_settles() {
    run_nip46_drop(DropSettlement::LocalRemove).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_drop_then_sign_in() {
    run_nip46_drop(DropSettlement::NewSignIn).await;
}

async fn run_nip46_drop(settlement: DropSettlement) {
    let shutdown_held = matches!(settlement, DropSettlement::Shutdown);
    let sign_in_requested = matches!(settlement, DropSettlement::NewSignIn);
    let expected_signed_out = !sign_in_requested;
    let peer = LoginPeer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RemovalFailureStore {
        inner: LocalFileSecretStore::new(dir.path()),
        refuse: std::sync::atomic::AtomicBool::new(false),
        native_removed: tokio::sync::Notify::new(),
    });
    let home = AccountHome::open_with_secret_store(dir.path(), store.clone());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let open_app = || {
        MarmotApp::with_relays_and_account_home_and_config(
            dir.path(),
            vec!["wss://account-relay.example".into()],
            AccountHome::open_with_secret_store(dir.path(), store.clone()),
            MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        )
        .with_test_relay_client(relay.clone())
    };
    let app = open_app();
    let runtime = app.runtime();
    let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
    let completed = runtime
        .login_external_signer(
            peer.user.public_key().to_hex(),
            TestExternalAccountSigner {
                keys: peer.user.clone(),
            },
            AccountSetupRequest {
                default_relays: endpoints(),
                bootstrap_relays: endpoints(),
                publish_missing_relay_lists: true,
                publish_initial_key_package: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let id = completed.account.account_id_hex;
    let signed_out = runtime
        .sign_out(
            &id,
            crate::runtime::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    app.register_external_signer(
        &id,
        TestExternalAccountSigner {
            keys: peer.user.clone(),
        },
    )
    .await
    .unwrap();
    let account = home.account(&id).unwrap();
    let originally_signed_out = account.signed_out;
    let cached = app
        .account_signer_for_summary(&account)
        .unwrap()
        .as_nostr_signer();
    let session = peer.session(&app);
    session.connect_async().await.unwrap();
    relay.fail_publishes_of_kind(KEY_PACKAGE_KIND);
    peer.hold_kp
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let login = {
        let runtime = runtime.clone();
        let session = session.clone();
        tokio::spawn(async move {
            runtime
                .nip46_login(session, endpoints(), endpoints(), Vec::new())
                .await
        })
    };
    let held = tokio::time::timeout(Duration::from_secs(10), peer.kp_seen.notified())
        .await
        .is_ok();
    let adopting = home.account(&id).is_ok_and(|account| !account.signed_out)
        && home
            .load_nip46_session(&id)
            .is_ok_and(|pairing| pairing.is_some());
    let pending = !login.is_finished();
    login.abort();
    let aborted = matches!(login.await, Err(error) if error.is_cancelled());

    let removed_before_reply = if matches!(settlement, DropSettlement::LocalRemove) {
        let removed = matches!(
            tokio::time::timeout(Duration::from_secs(5), runtime.nip46_remove(&id)).await,
            Ok(Ok(()))
        );
        if !removed {
            session.cancel();
        }
        removed
    } else {
        false
    };
    let mut sign_in = Box::pin(runtime.sign_in_account(&id));
    let mut early_sign_in = None;
    let sign_in_waited = if sign_in_requested {
        match tokio::time::timeout(Duration::from_millis(100), &mut sign_in).await {
            Ok(result) => {
                early_sign_in = Some(result);
                false
            }
            Err(_) => true,
        }
    } else {
        false
    };
    let mut newer_sign_in = false;
    let mut closed = false;
    let mut shutdown_before_release = false;
    let cleanup_observed = if shutdown_held {
        let mut closing = Box::pin(runtime.shutdown_and_close());
        let result = tokio::time::timeout(Duration::from_secs(10), &mut closing).await;
        shutdown_before_release = matches!(&result, Ok(Ok(())));
        closed = match result {
            Ok(result) => result.is_ok(),
            Err(_) => {
                session.cancel();
                peer.kp_release.notify_one();
                tokio::time::timeout(Duration::from_secs(10), &mut closing)
                    .await
                    .is_ok_and(|result| result.is_ok())
            }
        };
        closed
    } else {
        peer.kp_release.notify_one();
        let removed =
            tokio::time::timeout(Duration::from_secs(10), store.native_removed.notified())
                .await
                .is_ok();
        if sign_in_requested {
            newer_sign_in = match early_sign_in.take() {
                Some(result) => result.is_ok_and(|account| !account.signed_out && account.running),
                None => matches!(
                    tokio::time::timeout(Duration::from_secs(10), &mut sign_in).await,
                    Ok(Ok(account)) if !account.signed_out && account.running
                ),
            };
        }
        let settled = matches!(
            tokio::time::timeout(Duration::from_secs(10), runtime.nip46_resume(&id)).await,
            Ok(Err(AppError::Nip46(Nip46Error::Unavailable)))
        );
        removed && settled
    };
    drop(sign_in);

    let restored_signed_out = home.account(&id).is_ok_and(|account| account.signed_out);
    let pairing_removed = home
        .load_nip46_session(&id)
        .is_ok_and(|pairing| pairing.is_none());
    let secret_removed = store
        .has_secret_for_label(&format!(".nip46-client/{}", account.label))
        .is_ok_and(|exists| !exists);
    let journal_removed = home
        .account_setup_state(&id)
        .is_ok_and(|state| state.is_none());
    let content = serde_json::json!({
        "name": format!("native-drop-{}", Keys::generate().public_key()),
    })
    .to_string();
    let mut unsigned =
        EventBuilder::new(Kind::Metadata, content).finalize_unsigned(peer.user.public_key());
    unsigned.ensure_id();
    let expected = unsigned.id.unwrap();
    let signature = tokio::time::timeout(Duration::from_secs(5), cached.sign_event(unsigned)).await;
    let host_signed = matches!(
        &signature,
        Ok(Ok(signed)) if signed.id == expected
            && signed.pubkey == peer.user.public_key()
            && signed.verify().is_ok()
            && !peer.signed_profiles.lock().unwrap().contains(&expected)
    );
    let rejected: Vec<_> = relay
        .attempted_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == KEY_PACKAGE_KIND)
        .cloned()
        .collect();
    let real_rejection = !rejected.is_empty()
        && rejected.iter().all(|event| {
            let signed: Event =
                serde_json::from_str(&serde_json::to_string(event).unwrap()).unwrap();
            signed.verify().is_ok() && signed.pubkey == peer.user.public_key()
        });
    if !shutdown_held {
        closed = runtime.shutdown_and_close().await.is_ok();
    }
    drop(cached);
    drop(session);
    drop(runtime);
    drop(app);

    let app = open_app();
    let runtime = app.runtime();
    let reopened_signed_out = app
        .account_home()
        .account(&id)
        .is_ok_and(|account| account.signed_out);
    let reopened_pairing_removed = app
        .account_home()
        .load_nip46_session(&id)
        .is_ok_and(|pairing| pairing.is_none());
    let reopened_journal_removed = app
        .account_home()
        .account_setup_state(&id)
        .is_ok_and(|state| state.is_none());
    let reopened_ready = matches!(
        runtime.account_setup_readiness(&id),
        Ok(AccountSetupReadiness::NetworkReady)
    );
    let started = tokio::time::timeout(Duration::from_secs(10), runtime.start())
        .await
        .is_ok_and(|result| result.is_ok());
    let restart_inactive = runtime.accounts().managed_accounts().is_ok_and(|accounts| {
        accounts.iter().any(|account| {
            account.account_id_hex == id
                && account.signed_out == expected_signed_out
                && !account.running
        })
    });
    let reclosed = runtime.shutdown_and_close().await.is_ok();
    drop(runtime);
    drop(app);
    peer.close().await;

    assert!(signed_out.local_cleanup.completed && originally_signed_out);
    assert!(
        held && adopting && pending && aborted,
        "waiter must drop during Native adoption"
    );
    assert_eq!(
        restored_signed_out, expected_signed_out,
        "a later sign-in must follow rollback"
    );
    assert!(
        pairing_removed && secret_removed,
        "rollback must erase the attempt-created pairing"
    );
    assert!(
        cleanup_observed,
        "owned adoption must finish rollback after waiter drop"
    );
    assert!(
        journal_removed,
        "failed rebind must not create a setup journal"
    );
    assert!(
        host_signed,
        "the cached slot must use the original host for a real profile signature"
    );
    if shutdown_held {
        assert!(
            shutdown_before_release,
            "shutdown must settle rollback before signer release"
        );
    } else if !matches!(settlement, DropSettlement::LocalRemove) {
        assert!(
            real_rejection,
            "dropped adoption must reach real rejected KeyPackage publication"
        );
    }
    assert!(closed && started && reclosed);
    assert_eq!(reopened_signed_out, expected_signed_out);
    assert!(restart_inactive);
    assert!(
        reopened_pairing_removed && reopened_journal_removed && reopened_ready,
        "restart must retain no Native pairing or journal and preserve NetworkReady"
    );
    if sign_in_requested {
        assert!(
            newer_sign_in && sign_in_waited,
            "newer explicit sign-in must wait for the older adoption and then succeed"
        );
        assert!(
            !restored_signed_out,
            "older adoption rollback must not undo a newer completed sign-in"
        );
    }
    if matches!(settlement, DropSettlement::LocalRemove) {
        assert!(
            removed_before_reply,
            "local removal must interrupt owned adoption without signer response"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_remove_after_rollback() {
    let peer = LoginPeer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalFileSecretStore::new(dir.path()));
    let home = AccountHome::open_with_secret_store(dir.path(), store.clone());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let (entered, release) = fetcher.hold_fetches_for_kind(KIND_NIP65_RELAY_LIST);
    let mut app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec!["wss://account-relay.example".into()],
        home.clone(),
        MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        relay,
        fetcher,
        false,
    );
    let runtime = app.runtime();
    let session = peer.session(&app);
    session.connect_async().await.unwrap();
    let mut login = {
        let runtime = runtime.clone();
        let session = session.clone();
        tokio::spawn(async move {
            let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
            runtime
                .nip46_login(session, endpoints(), endpoints(), Vec::new())
                .await
        })
    };
    let held = tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .is_ok();
    let id = peer.user.public_key().to_hex();
    let account = home.account(&id).unwrap();
    let phase = home
        .account_setup_state(&id)
        .unwrap()
        .map(|setup| setup.phase);
    let removal = tokio::time::timeout(Duration::from_secs(5), runtime.nip46_remove(&id)).await;
    let account_gone = matches!(home.account(&id), Err(AccountHomeError::UnknownAccount(_)));
    let secret_gone = !store
        .has_secret_for_label(&format!(".nip46-client/{}", account.label))
        .unwrap();
    release.notify_one();
    if tokio::time::timeout(Duration::from_secs(5), &mut login)
        .await
        .is_err()
    {
        login.abort();
        let _ = login.await;
    }
    runtime.shutdown_and_close().await.unwrap();
    peer.close().await;
    assert!(held, "relay discovery must be held before publication");
    assert_eq!(
        phase,
        Some(marmot_account::AccountSetupPhase::LocalStateCreated)
    );
    assert!(
        account_gone && secret_gone,
        "cancellation must roll back the new account and its communication key"
    );
    assert!(
        matches!(
            removal,
            Ok(Err(AppError::AccountHome(
                AccountHomeError::UnknownAccount(_)
            )))
        ),
        "a rolled-back account is not a vault failure: {removal:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_login_needs_pairing() {
    #[derive(Clone, Copy, Debug)]
    enum PairingCase {
        Fresh,
        CachedDisconnected,
    }

    let peer = LoginPeer::new().await;
    let id = peer.user.public_key().to_hex();
    let mut observations = [
        (PairingCase::Fresh, false, false, false),
        (PairingCase::CachedDisconnected, false, false, false),
    ];
    for (case, refused, unpaired, absent) in &mut observations {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalFileSecretStore::new(dir.path()));
        let home = AccountHome::open_with_secret_store(dir.path(), store);
        let app = MarmotApp::with_relays_and_account_home_and_config(
            dir.path(),
            vec!["wss://account-relay.example".into()],
            home.clone(),
            MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        )
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let runtime = app.runtime();
        let session = peer.session(&app);
        if matches!(*case, PairingCase::CachedDisconnected) {
            session.connect_async().await.unwrap();
            session.disconnect();
        }
        let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
        let result = runtime
            .nip46_login(session.clone(), endpoints(), endpoints(), Vec::new())
            .await;
        *refused = matches!(result, Err(AppError::Nip46(Nip46Error::Unavailable)));
        *unpaired = session.status().state != crate::Nip46State::Ready;
        *absent = matches!(home.account(&id), Err(AccountHomeError::UnknownAccount(_)));
        runtime.shutdown_and_close().await.unwrap();
    }
    peer.close().await;
    assert!(
        observations
            .iter()
            .all(|(_, refused, unpaired, absent)| *refused && *unpaired && *absent),
        "unverified login must neither pair nor create an account: {observations:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_login_retains_retry() {
    let peer = LoginPeer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.fail_publishes_of_kind(KEY_PACKAGE_KIND);
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
    let runtime = app.runtime();
    let session = peer.session(&app);
    let communication_key = session.client_public_key().unwrap();
    session.connect_async().await.unwrap();
    let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
    runtime
        .nip46_login(session.clone(), endpoints(), endpoints(), Vec::new())
        .await
        .unwrap_err();
    let id = peer.user.public_key().to_hex();
    let account = home.account(&id).unwrap();
    assert!(!account.signed_out);
    assert_eq!(
        home.account_setup_state(&id).unwrap().unwrap().phase,
        marmot_account::AccountSetupPhase::KeyPackagePublicationStarted
    );
    assert_eq!(
        home.load_nip46_session(&id)
            .unwrap()
            .unwrap()
            .0
            .public_key(),
        communication_key
    );
    let rejected = relay
        .attempted_events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == KEY_PACKAGE_KIND)
        .unwrap()
        .id
        .clone();
    runtime.shutdown_and_close().await.unwrap();
    drop(session);
    drop(runtime);
    drop(app);
    relay.allow_all_publish_kinds();
    let app = open_app();
    let runtime = app.runtime();
    runtime.start().await.unwrap();
    let restored = runtime.nip46_resume(&id).await.unwrap();
    assert_eq!(restored.client_public_key().unwrap(), communication_key);
    restored.connect_async().await.unwrap();
    assert_eq!(
        runtime
            .nip46_login(restored, endpoints(), endpoints(), Vec::new())
            .await
            .unwrap()
            .account_id_hex,
        id
    );
    let published = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == KEY_PACKAGE_KIND)
        .unwrap()
        .clone();
    assert_eq!(published.id, rejected);
    let signed: Event = serde_json::from_str(&serde_json::to_string(&published).unwrap()).unwrap();
    signed.verify().unwrap();
    assert_eq!(signed.pubkey, peer.user.public_key());
    runtime.shutdown_and_close().await.unwrap();
    peer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_login_restores_host() {
    let peer = LoginPeer::new().await;
    for previous_grants in [None, Some(vec!["nip44_encrypt".to_owned()])] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalFileSecretStore::new(dir.path()));
        let home = AccountHome::open_with_secret_store(dir.path(), store.clone());
        let account = home
            .add_external_signer_account(&peer.user.public_key().to_hex())
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let open_app = || {
            MarmotApp::with_relays_and_account_home_and_config(
                dir.path(),
                vec!["wss://account-relay.example".into()],
                home.clone(),
                MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
            )
            .with_test_relay_client(relay.clone())
        };
        let app = open_app();
        let runtime = app.runtime();
        let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
        runtime
            .login_external_signer(
                account.account_id_hex.clone(),
                TestExternalAccountSigner {
                    keys: peer.user.clone(),
                },
                AccountSetupRequest {
                    default_relays: endpoints(),
                    bootstrap_relays: endpoints(),
                    publish_missing_relay_lists: true,
                    publish_initial_key_package: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            runtime.account_setup_readiness(&account.label).unwrap(),
            AccountSetupReadiness::NetworkReady
        );
        assert!(home.account_setup_state(&account.label).unwrap().is_none());
        let cached = app
            .account_signer_for_summary(&account)
            .unwrap()
            .as_nostr_signer();
        let session = peer.session(&app);
        session.connect_async().await.unwrap();
        let previous = if let Some(permissions) = previous_grants {
            let export: serde_json::Value =
                serde_json::from_str(&session.export().unwrap()).unwrap();
            let keys = Keys::parse(export["client_secret"].as_str().unwrap()).unwrap();
            let record = Nip46SessionRecord {
                version: 1,
                user_public_key: account.account_id_hex.clone(),
                remote_signer_public_key: peer.remote.public_key().to_hex(),
                client_public_key: keys.public_key().to_hex(),
                relays: vec![peer.url.clone()],
                name: "Prior approved pairing".into(),
                permission_version: 1,
                permissions,
            };
            home.store_nip46_session(&account.label, &keys, &record)
                .unwrap();
            Some(record)
        } else {
            None
        };
        relay.fail_publishes_of_kind(KEY_PACKAGE_KIND);
        assert!(matches!(
            runtime
                .nip46_login(session.clone(), endpoints(), endpoints(), Vec::new())
                .await,
            Err(AppError::Account(marmot_session::AccountError::KeyPackage(
                _
            )))
        ));
        let rejected = relay
            .attempted_events
            .lock()
            .unwrap()
            .iter()
            .find(|event| event.kind == KEY_PACKAGE_KIND)
            .cloned()
            .expect("Native rebind must reach KeyPackage publication");
        let rejected: Event =
            serde_json::from_str(&serde_json::to_string(&rejected).unwrap()).unwrap();
        rejected.verify().unwrap();
        assert_eq!(rejected.pubkey, peer.user.public_key());
        assert_eq!(
            runtime.account_setup_readiness(&account.label).unwrap(),
            AccountSetupReadiness::NetworkReady
        );
        assert!(home.account_setup_state(&account.label).unwrap().is_none());
        let mut unsigned = EventBuilder::new(Kind::Metadata, "{\"name\":\"retained callback\"}")
            .finalize_unsigned(peer.user.public_key());
        unsigned.ensure_id();
        let expected = unsigned.id.unwrap();
        let signed = cached.sign_event(unsigned).await.unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.id, expected);
        assert_eq!(signed.pubkey, peer.user.public_key());
        match previous {
            Some(previous) => {
                let (keys, record) = home.load_nip46_session(&account.label).unwrap().unwrap();
                assert_eq!(keys.public_key(), session.client_public_key().unwrap());
                assert_eq!(record, previous);
            }
            None => {
                assert!(home.load_nip46_session(&account.label).unwrap().is_none());
                assert!(
                    !store
                        .has_secret_for_label(&format!(".nip46-client/{}", account.label))
                        .unwrap()
                );
            }
        }
        assert_eq!(session.status().state, Nip46State::Disconnected);
        runtime.shutdown_and_close().await.unwrap();
        drop(cached);
        drop(session);
        drop(runtime);
        drop(app);
        let restarted = open_app();
        let runtime = restarted.runtime();
        assert_eq!(
            runtime.account_setup_readiness(&account.label).unwrap(),
            AccountSetupReadiness::NetworkReady
        );
        assert!(home.account_setup_state(&account.label).unwrap().is_none());
        runtime.shutdown_and_close().await.unwrap();
    }
    peer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_cold_rebind_failure() {
    let peer = LoginPeer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalFileSecretStore::new(dir.path()));
    let home = AccountHome::open_with_secret_store(dir.path(), store.clone());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let open_app = || {
        MarmotApp::with_relays_and_account_home_and_config(
            dir.path(),
            vec!["wss://account-relay.example".into()],
            home.clone(),
            MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        )
        .with_test_relay_client(relay.clone())
    };
    let app = open_app();
    let runtime = app.runtime();
    let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
    let completed = runtime
        .login_external_signer(
            peer.user.public_key().to_hex(),
            TestExternalAccountSigner {
                keys: peer.user.clone(),
            },
            AccountSetupRequest {
                default_relays: endpoints(),
                bootstrap_relays: endpoints(),
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let id = completed.account.account_id_hex;
    assert_eq!(completed.readiness, AccountSetupReadiness::NetworkReady);
    assert!(completed.key_package_bytes.is_some());
    assert!(home.account_setup_state(&id).unwrap().is_none());
    runtime.shutdown_and_close().await.unwrap();
    drop(runtime);
    drop(app);

    let app = open_app();
    let runtime = app.runtime();
    assert!(!app.has_external_signer(&id));
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    let session = peer.session(&app);
    session.connect_async().await.unwrap();
    assert!(matches!(
        runtime
            .nip46_login(session.clone(), Vec::new(), Vec::new(), Vec::new())
            .await,
        Err(AppError::MissingDefaultRelays)
    ));
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    assert!(home.account_setup_state(&id).unwrap().is_none());
    assert!(home.load_nip46_session(&id).unwrap().is_none());
    let account = home.account(&id).unwrap();
    assert!(
        !store
            .has_secret_for_label(&format!(".nip46-client/{}", account.label))
            .unwrap()
    );
    assert!(!app.has_external_signer(&id));
    runtime.shutdown_and_close().await.unwrap();
    drop(session);
    drop(runtime);
    drop(app);

    let app = open_app();
    let runtime = app.runtime();
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    assert!(home.account_setup_state(&id).unwrap().is_none());
    app.register_external_signer(
        &id,
        TestExternalAccountSigner {
            keys: peer.user.clone(),
        },
    )
    .await
    .unwrap();
    runtime.start().await.unwrap();
    assert!(
        runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .iter()
            .any(|account| account.account_id_hex == id && account.running)
    );
    let signer = app
        .account_signer_for_summary(&account)
        .unwrap()
        .as_nostr_signer();
    let mut unsigned = EventBuilder::new(Kind::Metadata, "{\"name\":\"restored host\"}")
        .finalize_unsigned(peer.user.public_key());
    unsigned.ensure_id();
    let expected = unsigned.id.unwrap();
    let signed = signer.sign_event(unsigned).await.unwrap();
    signed.verify().unwrap();
    assert_eq!(signed.id, expected);
    assert_eq!(signed.pubkey, peer.user.public_key());
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    assert!(home.account_setup_state(&id).unwrap().is_none());
    drop(signer);
    let signed_out = runtime
        .sign_out(
            &id,
            crate::runtime::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(signed_out.local_cleanup.completed);
    let session = peer.session(&app);
    session.connect_async().await.unwrap();
    assert!(matches!(
        runtime
            .nip46_login(session.clone(), Vec::new(), Vec::new(), Vec::new())
            .await,
        Err(AppError::MissingDefaultRelays)
    ));
    assert!(home.account(&id).unwrap().signed_out);
    assert!(home.account_setup_state(&id).unwrap().is_none());
    assert!(home.load_nip46_session(&id).unwrap().is_none());
    assert!(
        runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .iter()
            .any(|account| {
                account.account_id_hex == id && account.signed_out && !account.running
            })
    );
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    runtime.shutdown_and_close().await.unwrap();
    drop(session);
    drop(runtime);
    drop(app);
    let app = open_app();
    let runtime = app.runtime();
    assert!(home.account(&id).unwrap().signed_out);
    assert!(home.account_setup_state(&id).unwrap().is_none());
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    runtime.shutdown_and_close().await.unwrap();
    peer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_post_commit_failure() {
    let peer = LoginPeer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec!["wss://account-relay.example".into()],
        home.clone(),
        MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = app.runtime();
    let session = peer.session(&app);
    let communication_key = session.client_public_key().unwrap();
    session.connect_async().await.unwrap();
    *peer.completion_fault.lock().unwrap() = Some(home.clone());
    let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
    runtime
        .nip46_login(session.clone(), endpoints(), endpoints(), Vec::new())
        .await
        .unwrap_err();
    let id = peer.user.public_key().to_hex();
    let account = home.account(&id).unwrap();
    assert!(!account.signed_out);
    assert!(home.account_setup_state(&id).unwrap().is_none());
    assert_eq!(
        home.load_nip46_session(&id)
            .unwrap()
            .unwrap()
            .0
            .public_key(),
        communication_key
    );
    session.ping_async().await.unwrap();
    std::fs::remove_dir(
        home.account_dir(&account.label)
            .join(".account-setup-context.json"),
    )
    .unwrap();
    assert_eq!(
        runtime
            .nip46_login(session, endpoints(), endpoints(), Vec::new())
            .await
            .unwrap()
            .account_id_hex,
        id
    );
    runtime.shutdown_and_close().await.unwrap();
    peer.close().await;
}

struct RemovalFailureStore {
    inner: LocalFileSecretStore,
    refuse: std::sync::atomic::AtomicBool,
    native_removed: tokio::sync::Notify,
}

impl AccountSecretStore for RemovalFailureStore {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        self.inner.has_secret_for_label(label)
    }
    fn write_secret(
        &self,
        account: &marmot_account::AccountSummary,
        keys: &Keys,
    ) -> AccountHomeResult<()> {
        self.inner.write_secret(account, keys)
    }
    fn load_secret(&self, account: &marmot_account::AccountSummary) -> AccountHomeResult<Keys> {
        self.inner.load_secret(account)
    }
    fn remove_secret(&self, account: &marmot_account::AccountSummary) -> AccountHomeResult<()> {
        if account.label.starts_with(".nip46-client/")
            && self.refuse.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(AccountHomeError::SecretStoreUnavailable(
                "locked fixture vault".into(),
            ));
        }
        let native_existed = account.label.starts_with(".nip46-client/")
            && self.inner.has_secret_for_label(&account.label)?;
        self.inner.remove_secret(account)?;
        if native_existed {
            self.native_removed.notify_one();
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_erase_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RemovalFailureStore {
        inner: LocalFileSecretStore::new(dir.path()),
        refuse: std::sync::atomic::AtomicBool::new(false),
        native_removed: tokio::sync::Notify::new(),
    });
    let home = AccountHome::open_with_secret_store(dir.path(), store.clone());
    let user = Keys::generate();
    let client = Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let permissions = Nip46Session::permissions();
    home.store_nip46_session(
        &account.label,
        &client,
        &Nip46SessionRecord {
            version: 1,
            user_public_key: account.account_id_hex.clone(),
            remote_signer_public_key: Keys::generate().public_key().to_hex(),
            client_public_key: client.public_key().to_hex(),
            relays: vec!["wss://signer-relay.example".into()],
            name: "Deletion retry".into(),
            permission_version: permissions.version,
            permissions: permissions.grants,
        },
    )
    .unwrap();
    let app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec!["wss://account-relay.example".into()],
        home.clone(),
        MarmotAppConfig::white_noise(),
    );
    let runtime = app.runtime();
    let session = runtime.nip46_resume(&account.label).await.unwrap();
    store
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(session.erase_local(), Err(Nip46Error::Storage));
    assert_eq!(session.public_key(), Err(Nip46Error::LoggedOut));
    assert!(!app.has_external_signer(&account.account_id_hex));
    assert!(matches!(
        home.load_nip46_session(&account.label),
        Err(AccountHomeError::Io(_))
    ));
    store
        .refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    session.erase_local().unwrap();
    assert!(home.load_nip46_session(&account.label).unwrap().is_none());
    assert!(matches!(
        runtime.nip46_resume(&account.label).await,
        Err(AppError::Nip46(Nip46Error::Unavailable))
    ));
    runtime.shutdown_and_close().await.unwrap();
}

struct BindingHoldStore {
    inner: LocalFileSecretStore,
    hold_once: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

impl AccountSecretStore for BindingHoldStore {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        self.inner.has_secret_for_label(label)
    }
    fn write_secret(
        &self,
        account: &marmot_account::AccountSummary,
        keys: &Keys,
    ) -> AccountHomeResult<()> {
        self.inner.write_secret(account, keys)?;
        if account.label.starts_with(".nip46-client/")
            && self
                .hold_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.entered.notify_one();
            let (released, _) = self
                .changed
                .wait_timeout_while(
                    self.released.lock().unwrap(),
                    Duration::from_secs(10),
                    |released| !*released,
                )
                .unwrap();
            assert!(*released, "release the held protected-store write");
        }
        Ok(())
    }
    fn load_secret(&self, account: &marmot_account::AccountSummary) -> AccountHomeResult<Keys> {
        self.inner.load_secret(account)
    }
    fn remove_secret(&self, account: &marmot_account::AccountSummary) -> AccountHomeResult<()> {
        self.inner.remove_secret(account)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip46_disconnect_during_bind() {
    #[derive(Clone, Copy, Debug)]
    enum AfterDisconnect {
        StayDisconnected,
        Reconnect,
    }

    let peer = LoginPeer::new().await;
    let id = peer.user.public_key().to_hex();
    let mut observations = [
        (AfterDisconnect::StayDisconnected, false, false, false),
        (AfterDisconnect::Reconnect, false, false, false),
    ];
    for (mode, retired, absent, transport) in &mut observations {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(BindingHoldStore {
            inner: LocalFileSecretStore::new(dir.path()),
            hold_once: std::sync::atomic::AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            released: std::sync::Mutex::new(false),
            changed: std::sync::Condvar::new(),
        });
        let home = AccountHome::open_with_secret_store(dir.path(), store.clone());
        let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
        let (fetch_entered, fetch_release) = fetcher.hold_fetches_for_kind(KIND_NIP65_RELAY_LIST);
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relays_and_account_home_and_config(
            dir.path(),
            vec!["wss://account-relay.example".into()],
            home.clone(),
            MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        )
        .with_test_relay_client(relay.clone());
        app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
            Some(Duration::from_secs(120)),
            relay,
            fetcher,
            false,
        );
        let runtime = app.runtime();
        let session = peer.session(&app);
        session.connect_async().await.unwrap();
        let mut login = {
            let runtime = runtime.clone();
            let session = session.clone();
            tokio::spawn(async move {
                let endpoints = || vec![TransportEndpoint("wss://account-relay.example".into())];
                runtime
                    .nip46_login(session, endpoints(), endpoints(), Vec::new())
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(10), store.entered.notified())
            .await
            .unwrap();
        let disconnected = {
            let store = store.clone();
            let session = session.clone();
            tokio::spawn(async move {
                let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
                let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
                let parked = {
                    let release = release.clone();
                    tokio::spawn(async move {
                        entered_tx.send(()).unwrap();
                        let (released, _) = release
                            .1
                            .wait_timeout_while(
                                release.0.lock().unwrap(),
                                Duration::from_secs(10),
                                |released| !*released,
                            )
                            .unwrap();
                        assert!(*released, "release the parked Tokio worker");
                    })
                };
                entered_rx.await.unwrap();
                let write_release = std::thread::spawn(move || {
                    *store.released.lock().unwrap() = true;
                    store.changed.notify_one();
                });
                // Occupy both workers so disconnect wins before adoption resumes from binding.
                session.disconnect();
                write_release.join().unwrap();
                let state = session.status().state;
                *release.0.lock().unwrap() = true;
                release.1.notify_one();
                parked.await.unwrap();
                state
            })
            .await
            .unwrap()
        };
        assert_eq!(disconnected, Nip46State::Disconnected);
        let completed = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = &mut login => Some(result.unwrap()),
                _ = fetch_entered.notified() => None,
            }
        })
        .await
        .unwrap();
        if matches!(*mode, AfterDisconnect::Reconnect) {
            session.connect_async().await.unwrap();
        }
        fetch_release.notify_one();
        let result = match completed {
            Some(result) => result,
            None => tokio::time::timeout(Duration::from_secs(15), login)
                .await
                .unwrap()
                .unwrap(),
        };
        *retired = matches!(result, Err(AppError::Nip46(Nip46Error::Disconnected)));
        *absent = matches!(home.account(&id), Err(AccountHomeError::UnknownAccount(_)));
        *transport = session.status().state
            == match mode {
                AfterDisconnect::StayDisconnected => Nip46State::Disconnected,
                AfterDisconnect::Reconnect => Nip46State::Ready,
            };
        runtime.shutdown_and_close().await.unwrap();
    }
    peer.close().await;
    assert!(
        observations
            .iter()
            .all(|(_, retired, absent, transport)| *retired && *absent && *transport),
        "disconnect retires the old adoption without blocking a new explicit connection: {observations:?}"
    );
}
