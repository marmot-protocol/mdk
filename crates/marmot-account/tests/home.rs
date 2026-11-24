use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, mpsc};
use std::time::Duration;

use marmot_account::{
    AccountHome, AccountHomeError, AccountHomeResult, AccountSecretStore, AccountSetupKind,
    AccountSetupPhase, AccountSetupState, AccountSummary, AcquiredSecret, ExternalSecretMode,
    IosOptions, KeychainSecretStore, LocalFileSecretStore, Nip46Removal, Nip46SessionRecord,
    Nip46SessionWrite, SecretClaimMode, SecretCredential, SecretCredentialKind, SecretOrigin,
    SecretReleaseMode, SecretReleaseOutcome,
};
use nostr::nips::nip19::FromBech32;
use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Install an in-memory mock as the process-global default keyring store so
/// keychain-backed homes work on headless hosts; `AccountHome` skips its own
/// platform init when a default store already exists. Tests isolate their
/// entries through distinct service names.
///
/// `AccountHome::initialize_platform_keyring_store` also installs a
/// `keyring_core::mock::Store` under `#[cfg(test)]`. Whichever path runs
/// first wins; the other becomes a no-op because of the `get_default_store`
/// guard. Both code paths use the same process-global mock store, so test
/// isolation comes from distinct service names rather than separate stores.
fn install_mock_keyring() {
    static KEYRING_INIT: Once = Once::new();
    KEYRING_INIT.call_once(|| {
        if keyring_core::get_default_store().is_none() {
            let store = keyring_core::mock::Store::new().expect("create mock keyring store");
            keyring_core::set_default_store(store);
        }
    });
}

fn file_receipts(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let entries = match std::fs::read_dir(root.join(".owned-secrets-v1/receipts")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("reading credential receipts: {error}"),
    };
    entries.map(|entry| entry.unwrap().path()).collect()
}

#[cfg(unix)]
#[test]
fn cached_home_rejects_retarget() {
    let roots = tempfile::tempdir().unwrap();
    let original = roots.path().join("original");
    let copied = roots.path().join("copied");
    let alias = roots.path().join("home");
    std::fs::create_dir(&original).unwrap();
    std::os::unix::fs::symlink(&original, &alias).unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let initial =
        AccountHome::open_with_secret_store(&original, store.clone(), IosOptions::default());
    let account = initial.create_nostr_account().unwrap();
    let cached = AccountHome::open_with_secret_store(&alias, store.clone(), IosOptions::default());
    assert_eq!(
        cached
            .load_signing_keys(&account.label)
            .unwrap()
            .public_key()
            .to_hex(),
        account.account_id_hex
    );
    let copied_account = copied.join("accounts").join(&account.label);
    std::fs::create_dir_all(&copied_account).unwrap();
    for name in ["account.json", ".credential-ownership.json"] {
        std::fs::copy(
            cached.account_dir(&account.label).join(name),
            copied_account.join(name),
        )
        .unwrap();
    }
    std::fs::copy(
        original.join(".account-home-id.json"),
        copied.join(".account-home-id.json"),
    )
    .unwrap();
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&copied, &alias).unwrap();
    assert!(matches!(cached.load_signing_keys(&account.label),
        Err(AccountHomeError::SecretStore(error)) if error.contains("cached account home target changed")));
    let removal = cached.remove_account(&account.label);
    let original_home =
        AccountHome::open_with_secret_store(&original, store, IosOptions::default());
    let survivor = original_home.load_signing_keys(&account.label);
    assert!(
        removal.is_err(),
        "a cached home must not authorize copied owner receipts at a new root"
    );
    assert_eq!(
        survivor.unwrap().public_key().to_hex(),
        account.account_id_hex
    );
    assert_eq!(cached.account(&account.label).unwrap(), account);
}

#[test]
fn account_home_create_lists_and_reopens_generated_account_without_exposing_secret() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    let created = home.create_nostr_account().unwrap();
    assert_eq!(created.label, created.account_id_hex);
    assert_eq!(created.account_id_hex.len(), 64);
    assert!(created.local_signing);

    let listed = home.accounts().unwrap();
    assert_eq!(listed, vec![created.clone()]);
    let listed_json = serde_json::to_value(&listed[0]).unwrap();
    assert_eq!(listed_json["label"], created.account_id_hex);
    assert!(listed_json.get("secret_key_hex").is_none());

    let reopened = AccountHome::open(dir.path());
    assert_eq!(reopened.account(&created.account_id_hex).unwrap(), created);
    assert_eq!(
        reopened
            .load_signing_keys(&created.account_id_hex)
            .unwrap()
            .public_key()
            .to_hex(),
        created.account_id_hex
    );
}

#[test]
fn managed_reads_are_concurrent() {
    for file_backed in [false, true] {
        for kind in [
            SecretCredentialKind::Signing,
            SecretCredentialKind::ExternalDatabase,
            SecretCredentialKind::Nip46Session,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store: Arc<dyn AccountSecretStore> = if file_backed {
                Arc::new(LocalFileSecretStore::new(
                    directory.path(),
                    IosOptions::default(),
                ))
            } else {
                Arc::new(MemorySecretStore::default())
            };
            let home = AccountHome::open_with_secret_store(
                directory.path(),
                store.clone(),
                IosOptions::default(),
            );
            let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
            let account = if kind == SecretCredentialKind::Signing {
                home.import_account("reader", &user.secret_key().to_secret_hex())
                    .unwrap()
            } else {
                home.add_external_signer_account(&user.public_key().to_hex())
                    .unwrap()
            };
            match kind {
                SecretCredentialKind::Signing => {}
                SecretCredentialKind::ExternalDatabase => {
                    std::fs::write(
                        home.account_dir(&account.label)
                            .join(marmot_account::EXTERNAL_SQLCIPHER_SECRET_FILE),
                        "02".repeat(32),
                    )
                    .unwrap();
                    home.external_database_secret(&account.label, ExternalSecretMode::Existing)
                        .unwrap();
                }
                SecretCredentialKind::Nip46Session => {
                    let client = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
                    home.store_nip46_session(
                        &account.label,
                        &client,
                        &nip46_record(&user, &client),
                    )
                    .unwrap();
                }
            }
            let expected = vec![
                if kind == SecretCredentialKind::Signing {
                    1
                } else {
                    2
                };
                32
            ];
            let identity = std::fs::read(directory.path().join(".account-home-id.json")).unwrap();
            let ownership_path = home
                .account_dir(&account.label)
                .join(".credential-ownership.json");
            let ownership = std::fs::read(&ownership_path).unwrap();
            drop(home);
            std::fs::remove_file(directory.path().join(".account-mutation.lock")).unwrap();

            let (checkpoint, pause) = VaultCheckpoint::new();
            let paused = Arc::new(PausedReadStore {
                inner: store.clone(),
                pause,
            });
            let first = AccountHome::open_with_secret_store(
                directory.path(),
                paused,
                IosOptions::default(),
            );
            let second_store = if file_backed {
                Arc::new(LocalFileSecretStore::new(
                    directory.path(),
                    IosOptions::default(),
                )) as Arc<dyn AccountSecretStore>
            } else {
                store
            };
            let second = AccountHome::open_with_secret_store(
                directory.path(),
                second_store,
                IosOptions::default(),
            );
            let vault_writer = file_backed.then(|| {
                fs_private::try_acquire_private_exclusive_file_lease(
                    &directory.path().join(".credential-store.lock"),
                )
                .unwrap()
            });
            let label = account.label.clone();
            let reading = std::thread::spawn(move || read_managed_material(&first, &label, kind));
            checkpoint.wait_for_entry();
            let label = account.label.clone();
            let concurrent = checkpoint.before_release({
                let second = second.clone();
                move || read_managed_material(&second, &label, kind)
            });
            checkpoint.release();
            let initial = reading.join().unwrap();

            assert_eq!(concurrent.unwrap(), expected, "{file_backed:?} {kind:?}");
            assert_eq!(initial.unwrap(), expected, "{file_backed:?} {kind:?}");
            assert!(!directory.path().join(".account-mutation.lock").exists());
            assert_eq!(
                std::fs::read(directory.path().join(".account-home-id.json")).unwrap(),
                identity
            );
            assert_eq!(std::fs::read(&ownership_path).unwrap(), ownership);
            drop(vault_writer);

            let index = match kind {
                SecretCredentialKind::Signing => 0,
                SecretCredentialKind::ExternalDatabase => 1,
                SecretCredentialKind::Nip46Session => 2,
            };
            let mut pending: serde_json::Value = serde_json::from_slice(&ownership).unwrap();
            pending["credentials"][index]["origin"] = serde_json::Value::Null;
            let pending = serde_json::to_vec(&pending).unwrap();
            fs_private::write_private(&ownership_path, &pending).unwrap();
            let _root_writer = fs_private::try_acquire_private_exclusive_file_lease(
                &directory.path().join(".account-mutation.lock"),
            )
            .unwrap();
            assert!(
                matches!(read_managed_material(&second, &account.label, kind),
                Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            assert_eq!(std::fs::read(&ownership_path).unwrap(), pending);
        }
    }
}

fn read_managed_material(
    home: &AccountHome,
    label: &str,
    kind: SecretCredentialKind,
) -> AccountHomeResult<Vec<u8>> {
    match kind {
        SecretCredentialKind::Signing => Ok(home
            .load_signing_keys(label)?
            .secret_key()
            .as_secret_bytes()
            .to_vec()),
        SecretCredentialKind::ExternalDatabase => Ok(home
            .external_database_secret(label, ExternalSecretMode::Existing)?
            .to_vec()),
        SecretCredentialKind::Nip46Session => Ok(home
            .load_nip46_session(label)?
            .expect("stored session")
            .0
            .secret_key()
            .as_secret_bytes()
            .to_vec()),
    }
}

#[test]
fn legacy_reads_need_writer() {
    let directory = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let account = AccountSummary {
        label: "legacy-reader".into(),
        account_id_hex: keys.public_key().to_hex(),
        local_signing: true,
        external_signing: false,
        signed_out: false,
        unlinked: false,
    };
    let home = AccountHome::open(directory.path());
    let account_dir = home.account_dir(&account.label);
    fs_private::create_dir_all_private(&account_dir).unwrap();
    fs_private::write_private(
        &account_dir.join("account.json"),
        &serde_json::to_vec(&account).unwrap(),
    )
    .unwrap();
    let legacy = serde_json::to_vec(
        &serde_json::json!({ "secret_key_hex": keys.secret_key().to_secret_hex() }),
    )
    .unwrap();
    fs_private::write_private(&account_dir.join("secret.json"), &legacy).unwrap();
    let writer = fs_private::try_acquire_private_exclusive_file_lease(
        &directory.path().join(".account-mutation.lock"),
    )
    .unwrap();

    assert!(matches!(home.load_signing_keys(&account.label),
        Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock));
    assert!(!directory.path().join(".account-home-id.json").exists());
    assert!(!account_dir.join(".credential-ownership.json").exists());
    assert!(!directory.path().join(".owned-secrets-v1").exists());
    drop(writer);

    assert_eq!(
        home.load_signing_keys(&account.label).unwrap().public_key(),
        keys.public_key()
    );
    assert_eq!(
        std::fs::read(account_dir.join("secret.json")).unwrap(),
        legacy
    );
    assert_eq!(file_receipts(directory.path()).len(), 1);
}

#[test]
fn file_receipts_are_private() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    let created = home.create_nostr_account().unwrap();

    let secret_path = file_receipts(dir.path()).pop().unwrap();
    let raw = std::fs::read_to_string(&secret_path).unwrap();
    assert!(
        raw.contains(
            &home
                .load_signing_keys(&created.label)
                .unwrap()
                .secret_key()
                .to_secret_hex()
        )
    );

    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(secret_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn account_home_import_accepts_nsec_and_reopens_the_same_identity() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let imported = home.import_nostr_account(nsec).unwrap();
    let reopened = AccountHome::open(dir.path());

    assert_eq!(
        reopened.account(&imported.account_id_hex).unwrap(),
        imported
    );
    assert_eq!(
        reopened
            .load_signing_keys(&imported.account_id_hex)
            .unwrap()
            .public_key()
            .to_hex(),
        imported.account_id_hex
    );
}

#[test]
fn runtime_import_recovers_journal_before_secret_or_account_record() {
    let dir = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account_id = keys.public_key().to_hex();
    let account_dir = dir.path().join("accounts").join(&account_id);
    std::fs::create_dir_all(&account_dir).unwrap();
    std::fs::write(
        account_dir.join(".account-setup.json"),
        serde_json::to_vec(&AccountSetupState {
            account_id_hex: account_id.clone(),
            reused_account_id_credential: false,
            kind: AccountSetupKind::ImportedIdentity,
            phase: AccountSetupPhase::LocalStateCreated,
        })
        .unwrap(),
    )
    .unwrap();

    let home = AccountHome::open(dir.path());
    let imported = home
        .import_nostr_account_idempotent(&keys.secret_key().to_secret_hex())
        .unwrap();

    assert_eq!(imported.account().account_id_hex, account_id);
    assert_eq!(home.accounts().unwrap().len(), 1);
    assert_eq!(
        home.load_signing_keys(&account_id).unwrap().public_key(),
        keys.public_key()
    );
}

#[test]
fn generated_setup_admission() {
    for fail_write in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemorySecretStore::default());
        store
            .fail_write_after_commit
            .store(fail_write, Ordering::SeqCst);
        let home =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        let other =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        let checkpoint = store.pause_once("write");
        let create = std::thread::spawn(move || home.create_nostr_account_for_setup());
        checkpoint.wait_for_entry();
        let directories = std::fs::read_dir(dir.path().join("accounts"))
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let journal = directories
            .first()
            .and_then(|path| std::fs::read(path.join(".account-setup.json")).ok())
            .and_then(|bytes| serde_json::from_slice::<AccountSetupState>(&bytes).ok());
        let (visible, credentials) = checkpoint.before_release({
            let other = other.clone();
            let store = store.clone();
            move || (other.accounts(), store.keys.lock().unwrap().len())
        });
        checkpoint.release();
        let result = create.join().unwrap();

        assert_eq!(directories.len(), 1);
        assert!(visible.unwrap().is_empty());
        assert_eq!(credentials, 0);
        let account = if fail_write {
            assert!(matches!(result, Err(AccountHomeError::SecretStore(error))
                if error == "injected write failure"));
            assert!(other.accounts().unwrap().is_empty());
            store.fail_lookup.store(true, Ordering::SeqCst);
            let ownership_path = directories[0].join(".credential-ownership.json");
            let ownership = std::fs::read(&ownership_path).unwrap();
            *store.load_error.lock().unwrap() = Some(AccountHomeError::SecretStore(
                "exact receipt temporarily unavailable".into(),
            ));
            assert!(matches!(other.resumable_generated_account_setup(),
                Err(AccountHomeError::SecretStore(error)) if error == "exact receipt temporarily unavailable"));
            assert_eq!(std::fs::read(ownership_path).unwrap(), ownership);
            assert!(directories[0].join(".account-setup.json").is_file());
            other.resumable_generated_account_setup().unwrap().unwrap()
        } else {
            result.unwrap()
        };
        assert_eq!(
            journal,
            Some(AccountSetupState {
                account_id_hex: account.account_id_hex.clone(),
                reused_account_id_credential: false,
                kind: AccountSetupKind::GeneratedIdentity,
                phase: AccountSetupPhase::LocalStateCreated,
            })
        );
        assert_eq!(other.account(&account.label).unwrap(), account);
        assert_eq!(
            other
                .load_signing_keys(&account.label)
                .unwrap()
                .public_key()
                .to_hex(),
            account.account_id_hex
        );
    }
}

#[test]
fn generated_setup_key_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let reopened = AccountHome::open(dir.path());
    assert_eq!(account.label, account.account_id_hex);
    assert!(account.local_signing);
    assert!(!account.external_signing);
    assert_eq!(
        reopened
            .load_signing_keys(&account.label)
            .unwrap()
            .public_key()
            .to_hex(),
        account.account_id_hex
    );
    assert_eq!(
        reopened.resumable_generated_account_setup().unwrap(),
        Some(account.clone())
    );
    let directory = reopened.account_dir(&account.label);
    let journal = std::fs::read(directory.join(".account-setup.json")).unwrap();
    let state: AccountSetupState = serde_json::from_slice(&journal).unwrap();
    assert_eq!(state.account_id_hex, account.account_id_hex);
    assert_eq!(state.kind, AccountSetupKind::GeneratedIdentity);
    assert_eq!(state.phase, AccountSetupPhase::LocalStateCreated);
    std::fs::remove_file(directory.join("account.json")).unwrap();
    assert_eq!(
        reopened.resumable_generated_account_setup().unwrap(),
        Some(account.clone())
    );
    assert_eq!(reopened.account(&account.label).unwrap(), account);

    std::fs::remove_file(directory.join("account.json")).unwrap();
    let secret_path = file_receipts(dir.path()).pop().unwrap();
    let mut secret: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&secret_path).unwrap()).unwrap();
    secret["secret_key_hex"] = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex()
        .into();
    std::fs::write(secret_path, serde_json::to_vec(&secret).unwrap()).unwrap();
    assert!(matches!(
        reopened.resumable_generated_account_setup(),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    assert!(!directory.join("account.json").exists());
    assert_eq!(
        std::fs::read(directory.join(".account-setup.json")).unwrap(),
        journal
    );
}

#[test]
fn runtime_import_recovers_journal_and_secret_before_account_record() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let keys = nostr::prelude::Keys::generate();
    let account_id = keys.public_key().to_hex();
    let account = home
        .import_nostr_account(&keys.secret_key().to_secret_hex())
        .unwrap();
    std::fs::remove_file(home.account_dir(&account.label).join("account.json")).unwrap();
    std::fs::write(
        home.account_dir(&account.label).join(".account-setup.json"),
        serde_json::to_vec(&AccountSetupState {
            account_id_hex: account_id.clone(),
            reused_account_id_credential: false,
            kind: AccountSetupKind::ImportedIdentity,
            phase: AccountSetupPhase::LocalStateCreated,
        })
        .unwrap(),
    )
    .unwrap();

    let imported = home
        .import_nostr_account_idempotent(&keys.secret_key().to_secret_hex())
        .unwrap();

    assert_eq!(imported.account().account_id_hex, account_id);
    assert_eq!(home.accounts().unwrap().len(), 1);
}

#[test]
fn setup_phase_update_fails_when_journal_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account().unwrap();

    assert!(matches!(
        home.set_account_setup_phase(
            &account.label,
            AccountSetupPhase::KeyPackagePublicationStarted
        ),
        Err(AccountHomeError::AccountSetupStateMissing)
    ));
}

/// Runtime readiness polls read the journal while background setup advances
/// it. Holding a reader's handle across the phase write pins the widest race
/// window deterministically: the reader must still see one complete journal.
#[cfg(unix)]
#[test]
fn setup_phase_update_leaves_an_open_journal_reader_a_complete_record() {
    use std::io::Read;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let journal = home.account_dir(&account.label).join(".account-setup.json");
    let mut reader = std::fs::File::open(&journal).unwrap();

    home.set_account_setup_phase(&account.label, AccountSetupPhase::LocalReady)
        .unwrap();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    let observed: AccountSetupState = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(observed.phase, AccountSetupPhase::LocalStateCreated);
    assert_eq!(
        home.account_setup_state(&account.label)
            .unwrap()
            .unwrap()
            .phase,
        AccountSetupPhase::LocalReady
    );
    assert_eq!(
        std::fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// Readiness also reads the onboarding checkpoint, which every onboarding step
/// rewrites. An open reader must keep the whole previous checkpoint.
#[cfg(unix)]
#[test]
fn onboarding_checkpoint_rewrite_leaves_an_open_reader_the_previous_checkpoint() {
    use std::io::Read;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account().unwrap();
    home.set_account_onboarding(&account.label, br#"{"revision":1}"#)
        .unwrap();
    let checkpoint = home.account_dir(&account.label).join("onboarding.json");
    let mut reader = std::fs::File::open(&checkpoint).unwrap();

    home.set_account_onboarding(&account.label, br#"{"revision":2}"#)
        .unwrap();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, br#"{"revision":1}"#);
    assert_eq!(
        home.account_onboarding(&account.label).unwrap().unwrap(),
        br#"{"revision":2}"#
    );
}

#[test]
fn generated_setup_context_is_private_and_removed_with_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let context = br#"{"default_relays":["wss://relay.example"]}"#;

    home.set_account_setup_context(&account.label, context)
        .unwrap();

    assert_eq!(
        home.account_setup_context(&account.label)
            .unwrap()
            .as_deref(),
        Some(context.as_slice())
    );
    let context_path = home
        .account_dir(&account.label)
        .join(".account-setup-context.json");
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&context_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    home.complete_account_setup(&account.label).unwrap();
    assert!(!context_path.exists());
    assert!(home.account_setup_state(&account.label).unwrap().is_none());
}

#[test]
fn generated_setup_context_is_absent_until_written() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account_for_setup().unwrap();

    assert!(
        home.account_setup_context(&account.label)
            .unwrap()
            .is_none()
    );
}

#[test]
fn generated_setup_context_write_requires_a_setup_journal() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account().unwrap();

    assert!(matches!(
        home.set_account_setup_context(&account.label, b"{}"),
        Err(AccountHomeError::AccountSetupStateMissing)
    ));
}

#[test]
fn account_home_idempotent_import_reuses_existing_identity() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let first = home.import_account_idempotent("agent", nsec).unwrap();
    let second = home.import_account_idempotent("agent", nsec).unwrap();

    assert_eq!(second, first);
    assert_eq!(home.accounts().unwrap(), vec![first]);
}

#[test]
fn account_home_idempotent_import_reactivates_signed_out_identity() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    home.import_account_idempotent("agent", nsec).unwrap();
    home.set_account_signed_out("agent", true).unwrap();

    let imported = home.import_account_idempotent("agent", nsec).unwrap();

    assert!(!imported.signed_out);
    assert!(!home.account("agent").unwrap().signed_out);
}

/// An account whose device was unlinked stays signed out: neither signing in
/// nor importing its key again reactivates it, and removing it clears the
/// mark with the rest of the account (mdk#2628 D67).
#[test]
fn account_home_unlinked_account_stays_signed_out_until_removed() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    home.import_account_idempotent("agent", nsec).unwrap();

    let unlinked = home.mark_account_unlinked("agent").unwrap();
    assert!(unlinked.unlinked && unlinked.signed_out);
    assert_eq!(home.account("agent").unwrap(), unlinked);
    assert_eq!(home.mark_account_unlinked("agent").unwrap(), unlinked);

    assert!(matches!(
        home.set_account_signed_out("agent", false),
        Err(AccountHomeError::AccountUnlinked(label)) if label == "agent"
    ));
    assert!(matches!(
        home.import_account_idempotent("agent", nsec),
        Err(AccountHomeError::AccountUnlinked(label)) if label == "agent"
    ));
    assert_eq!(
        home.set_account_signed_out("agent", true).unwrap(),
        unlinked
    );
    assert_eq!(home.account("agent").unwrap(), unlinked);

    home.remove_account("agent").unwrap();
    let again = home.import_account_idempotent("agent", nsec).unwrap();
    assert!(!again.unlinked && !again.signed_out);
}

#[test]
fn account_home_idempotent_import_repairs_interrupted_record_first_import() {
    let dir = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account = AccountSummary {
        label: "agent".to_owned(),
        account_id_hex: keys.public_key().to_hex(),
        local_signing: true,
        external_signing: false,
        signed_out: false,
        unlinked: false,
    };
    let account_dir = dir.path().join("accounts").join(&account.label);
    std::fs::create_dir_all(&account_dir).unwrap();
    std::fs::write(
        account_dir.join("account.json"),
        serde_json::to_vec(&account).unwrap(),
    )
    .unwrap();
    let home = AccountHome::open(dir.path());

    let repaired = home
        .import_account_idempotent("agent", &keys.secret_key().to_secret_hex())
        .unwrap();

    assert_eq!(repaired, account);
    assert_eq!(
        home.load_signing_keys("agent").unwrap().public_key(),
        keys.public_key()
    );
}

#[test]
fn account_home_accounts_skips_unreadable_records() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    let good = home.create_account("good").unwrap();
    let corrupted = home.create_account("corrupted").unwrap();
    std::fs::write(
        dir.path()
            .join("accounts")
            .join(&corrupted.label)
            .join("account.json"),
        b"{",
    )
    .unwrap();

    assert_eq!(home.accounts().unwrap(), vec![good]);
    assert!(matches!(
        home.accounts_strict(),
        Err(AccountHomeError::Json(_))
    ));
    assert!(matches!(
        home.account(&corrupted.label),
        Err(AccountHomeError::Json(_))
    ));
}

#[cfg(unix)]
#[test]
fn strict_catalog_does_not_treat_a_metadata_probe_error_as_an_empty_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    // A symlink loop deterministically fails metadata probing, including under root.
    std::os::unix::fs::symlink("accounts", dir.path().join("accounts")).unwrap();
    assert!(
        home.accounts().unwrap().is_empty(),
        "legacy best-effort behavior"
    );
    assert!(matches!(
        home.accounts_strict(),
        Err(AccountHomeError::Io(_))
    ));
}

#[cfg(unix)]
fn file_mode(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn loosen_to_umask_default(path: &std::path::Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(unix)]
#[test]
fn account_records_and_key_security_markers_are_written_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    let accounts = [
        home.create_nostr_account().unwrap(),
        home.create_account("labelled").unwrap(),
        // The `wn-agent import-identity` path.
        home.import_account_idempotent("agent", nsec).unwrap(),
        home.add_external_signer_account(&nostr::prelude::Keys::generate().public_key().to_hex())
            .unwrap(),
        home.add_public_account(&nostr::prelude::Keys::generate().public_key().to_hex())
            .unwrap(),
    ];
    for account in &accounts {
        let account_dir = home.account_dir(&account.label);
        assert_eq!(file_mode(&account_dir), 0o700);
        assert_eq!(file_mode(&account_dir.join("account.json")), 0o600);
    }

    home.mark_key_handled_insecurely("agent").unwrap();

    assert_eq!(
        file_mode(&home.account_dir("agent").join("key-security.json")),
        0o600
    );
}

/// Builds before mdk#2569 wrote both records at the process umask.
#[cfg(unix)]
#[test]
fn reading_legacy_umask_records_tightens_them_owner_only() {
    use nostr::nips::nip19::ToBech32;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let labelled = home.create_account("labelled").unwrap();
    let generated = home.create_nostr_account().unwrap();
    home.mark_key_handled_insecurely("labelled").unwrap();
    let listed = home.accounts().unwrap();
    let record = |label: &str| home.account_dir(label).join("account.json");
    let marker = home.account_dir("labelled").join("key-security.json");
    for path in [record("labelled"), record(&generated.label), marker.clone()] {
        loosen_to_umask_default(&path);
    }

    assert_eq!(home.accounts().unwrap(), listed);
    assert_eq!(file_mode(&record("labelled")), 0o600);
    assert_eq!(file_mode(&record(&generated.label)), 0o600);

    loosen_to_umask_default(&record("labelled"));
    assert_eq!(home.account("labelled").unwrap(), labelled);
    assert_eq!(file_mode(&record("labelled")), 0o600);

    loosen_to_umask_default(&record(&generated.label));
    let npub = nostr::prelude::PublicKey::from_hex(&generated.account_id_hex)
        .unwrap()
        .to_bech32()
        .unwrap();
    assert_eq!(home.account(&npub).unwrap(), generated);
    assert_eq!(file_mode(&record(&generated.label)), 0o600);

    assert_eq!(home.key_security_byte("labelled").unwrap(), 0x00);
    assert_eq!(file_mode(&marker), 0o600);

    for path in [
        record("labelled"),
        home.account_dir("labelled")
            .join(".credential-ownership.json"),
        dir.path().join(".account-home-id.json"),
    ] {
        loosen_to_umask_default(&path);
        let writer = fs_private::try_acquire_private_exclusive_file_lease(
            &dir.path().join(".account-mutation.lock"),
        )
        .unwrap();
        let reopened = AccountHome::open(dir.path());
        assert!(matches!(reopened.load_signing_keys("labelled"),
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock));
        assert_eq!(file_mode(&path), 0o644);
        drop(writer);
        assert_eq!(
            reopened
                .load_signing_keys("labelled")
                .unwrap()
                .public_key()
                .to_hex(),
            labelled.account_id_hex
        );
        assert_eq!(file_mode(&path), 0o600);
    }
}

/// The no-follow tightening cannot reach a symlinked record, so reading it
/// fails instead of skipping the tightening; the best-effort catalog skips
/// and reports it like any other unreadable record.
#[cfg(unix)]
#[test]
fn untightenable_account_record_fails_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let good = home.create_account("good").unwrap();
    home.create_account("linked").unwrap();
    let record = home.account_dir("linked").join("account.json");
    let target = dir.path().join("elsewhere.json");
    std::fs::rename(&record, &target).unwrap();
    loosen_to_umask_default(&target);
    std::os::unix::fs::symlink(&target, &record).unwrap();

    assert_eq!(home.accounts().unwrap(), vec![good]);
    assert!(matches!(
        home.accounts_strict(),
        Err(AccountHomeError::Io(_))
    ));
    assert!(matches!(
        home.account("linked"),
        Err(AccountHomeError::Io(_))
    ));
    assert_eq!(file_mode(&target), 0o644);
}

#[test]
fn account_home_rejects_path_like_labels() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    let secret_hex = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex();

    assert!(matches!(
        home.import_account("../alice", &secret_hex),
        Err(AccountHomeError::InvalidAccountLabel(label)) if label == "../alice"
    ));
    assert!(!dir.path().join("accounts").join("../alice").exists());
    home.import_nostr_account(nsec).unwrap();
    assert!(matches!(
        home.import_nostr_account(nsec),
        Err(AccountHomeError::AccountExists(_))
    ));
}

#[test]
fn account_home_rejects_windows_drive_relative_labels() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let secret_hex = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex();

    assert!(matches!(
        home.import_account("C:evil", &secret_hex),
        Err(AccountHomeError::InvalidAccountLabel(label)) if label == "C:evil"
    ));
    assert!(!dir.path().join("accounts").join("C:evil").exists());
}

#[test]
fn account_home_rejects_control_characters_in_labels() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let secret_hex = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex();

    for label in ["evil\nlabel", "evil\rlabel", "evil\u{1b}[2Klabel"] {
        assert!(matches!(
            home.import_account(label, &secret_hex),
            Err(AccountHomeError::InvalidAccountLabel(rejected)) if rejected == label
        ));
        assert!(!dir.path().join("accounts").join(label).exists());
    }
}

#[test]
fn account_home_can_derive_identity_before_importing_secret() {
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let account_id = AccountHome::account_id_for_secret(nsec).unwrap();

    assert_eq!(account_id.len(), 64);
}

#[test]
fn account_home_can_store_public_nostr_identity_without_secret() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = "0000000000000000000000000000000000000000000000000000000000000001";

    let account = home.add_public_account(public_key).unwrap();

    assert_eq!(account.account_id_hex.len(), 64);
    assert!(!account.local_signing);
    assert_eq!(home.account(public_key).unwrap(), account);
    assert!(home.account_setup_state(public_key).unwrap().is_none());
    assert!(matches!(
        home.load_signing_keys(public_key),
        Err(AccountHomeError::SecretNotFound(_))
    ));
}

#[test]
fn account_home_can_store_external_signer_identity_without_secret() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = nostr::prelude::Keys::generate().public_key().to_hex();

    let account = home.add_external_signer_account(&public_key).unwrap();

    assert_eq!(account.account_id_hex, public_key);
    assert!(!account.local_signing);
    assert!(account.external_signing);
    assert!(account.can_sign());
    assert!(account.is_active_signing());
    assert!(!account.is_active_local_signing());
    assert_eq!(home.account(&public_key).unwrap(), account);
    assert!(home.account_setup_state(&public_key).unwrap().is_none());
    assert!(matches!(
        home.load_signing_keys(&public_key),
        Err(AccountHomeError::SecretNotFound(_))
    ));
}

#[test]
fn account_home_upgrades_public_identity_to_external_signer_identity() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = nostr::prelude::Keys::generate().public_key().to_hex();
    let public = home.add_public_account(&public_key).unwrap();

    let external = home.add_external_signer_account(&public_key).unwrap();

    assert_eq!(external.account_id_hex, public.account_id_hex);
    assert!(!external.local_signing);
    assert!(external.external_signing);
    assert_eq!(home.accounts().unwrap(), vec![external]);
}

#[test]
fn nonlocal_setup_admission() {
    for external in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let public_key = nostr::prelude::Keys::generate().public_key().to_hex();
        let admit: fn(&AccountHome, &str) -> AccountHomeResult<AccountSummary> = if external {
            AccountHome::add_external_signer_for_setup
        } else {
            AccountHome::add_public_account_for_setup
        };
        let account = admit(&home, &public_key).unwrap();
        let expected = AccountSetupState {
            account_id_hex: public_key.clone(),
            reused_account_id_credential: false,
            kind: if external {
                AccountSetupKind::ExternalSigner
            } else {
                AccountSetupKind::PublicIdentity
            },
            phase: AccountSetupPhase::LocalStateCreated,
        };
        let reopened = AccountHome::open(dir.path());
        assert_eq!(reopened.account(&public_key).unwrap(), account);
        assert!(!account.local_signing);
        assert_eq!(account.external_signing, external);
        assert_eq!(
            reopened.account_setup_state(&public_key).unwrap(),
            Some(expected)
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(home.account_dir(&public_key).join(".account-setup.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        if external {
            home.set_account_setup_phase(&public_key, AccountSetupPhase::LocalReady)
                .unwrap();
            assert_eq!(admit(&home, &public_key).unwrap(), account);
            assert_eq!(
                home.account_setup_state(&public_key)
                    .unwrap()
                    .unwrap()
                    .phase,
                AccountSetupPhase::LocalReady
            );
        } else {
            assert!(matches!(admit(&home, &public_key),
                Err(AccountHomeError::AccountExists(label)) if label == public_key));
        }
    }
}

#[test]
fn signing_rejects_nonlocal() {
    for external in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let keys = nostr::prelude::Keys::generate();
        let label = keys.public_key().to_hex();
        let secret = keys.secret_key().to_secret_hex();
        let admit = if external {
            AccountHome::add_external_signer_account
        } else {
            AccountHome::add_public_account
        };
        let previous = admit(&home, &label).unwrap();
        let directory = home.account_dir(&label);
        std::fs::remove_file(directory.join("account.json")).unwrap();
        let ownership_path = directory.join(".credential-ownership.json");
        let ownership = std::fs::read(&ownership_path).unwrap();
        drop(home);

        let reopened = AccountHome::open(dir.path());
        for attempt in [
            reopened.import_account(&label, &secret),
            reopened.import_account_idempotent(&label, &secret),
            reopened
                .import_nostr_account_idempotent(&secret)
                .map(|import| import.account().clone()),
        ] {
            assert!(
                matches!(attempt, Err(AccountHomeError::AccountExists(account)) if account == label)
            );
        }
        assert!(file_receipts(dir.path()).is_empty());
        assert!(!directory.join("account.json").exists());
        assert!(!directory.join(".account-setup.json").exists());
        assert_eq!(std::fs::read(ownership_path).unwrap(), ownership);
        assert_eq!(admit(&reopened, &label).unwrap(), previous);
    }
}

#[cfg(unix)]
#[test]
fn setup_journal_write_is_atomic() {
    use std::os::unix::fs::symlink;

    for (external, promote) in [(false, false), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let public_key = nostr::prelude::Keys::generate().public_key().to_hex();
        let previous = promote.then(|| home.add_public_account(&public_key).unwrap());
        let account_dir = home.account_dir(&public_key);
        let saved = dir.path().join("saved");
        if promote {
            std::fs::rename(&account_dir, &saved).unwrap();
        } else {
            std::fs::create_dir_all(account_dir.parent().unwrap()).unwrap();
            std::fs::create_dir(&saved).unwrap();
        }
        symlink(&saved, &account_dir).unwrap();
        let admit: fn(&AccountHome, &str) -> AccountHomeResult<AccountSummary> = if external {
            AccountHome::add_external_signer_for_setup
        } else {
            AccountHome::add_public_account_for_setup
        };

        assert!(matches!(
            admit(&home, &public_key),
            Err(AccountHomeError::Io(error))
                if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::EMLINK))
        ));
        assert!(!saved.join(".account-setup.json").exists());
        assert_eq!(
            home.accounts().unwrap(),
            previous.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(saved.join("account.json").exists(), promote);

        std::fs::remove_file(&account_dir).unwrap();
        std::fs::rename(saved, account_dir).unwrap();
        let account = admit(&home, &public_key).unwrap();
        assert_eq!(account.external_signing, external);
        assert_eq!(
            home.account_setup_state(&public_key)
                .unwrap()
                .unwrap()
                .phase,
            AccountSetupPhase::LocalStateCreated
        );
    }
}

#[test]
fn setup_journal_error_is_hidden() {
    for external in [false, true] {
        for corrupt in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let home = AccountHome::open(dir.path());
            let public_key = nostr::prelude::Keys::generate().public_key().to_hex();
            let account_dir = home.account_dir(&public_key);
            std::fs::create_dir_all(&account_dir).unwrap();
            let journal = account_dir.join(".account-setup.json");
            if corrupt {
                std::fs::write(&journal, b"interrupted journal").unwrap();
            } else {
                std::fs::create_dir(&journal).unwrap();
            }
            let result = if external {
                home.add_external_signer_for_setup(&public_key)
            } else {
                home.add_public_account_for_setup(&public_key)
            };

            if corrupt {
                assert!(matches!(result, Err(AccountHomeError::Json(_))));
                assert_eq!(std::fs::read(&journal).unwrap(), b"interrupted journal");
            } else {
                assert!(matches!(result, Err(AccountHomeError::Io(error))
                if error.kind() == std::io::ErrorKind::IsADirectory
                    || error.kind() == std::io::ErrorKind::PermissionDenied));
                assert!(journal.is_dir());
            }
            assert!(!account_dir.join("account.json").exists());
            assert!(home.accounts().unwrap().is_empty());
        }
    }
}

#[test]
fn setup_admission_keeps_journal() {
    for (external, recorded) in [(false, false), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let public_key = nostr::prelude::Keys::generate().public_key().to_hex();
        let previous = home.add_public_account(&public_key).unwrap();
        let state = home
            .begin_account_setup_with(
                &previous,
                true,
                AccountSetupKind::InteractiveIdentity,
                AccountSetupPhase::BootstrapPublicationStarted,
            )
            .unwrap();
        let account_dir = home.account_dir(&public_key);
        let journal = account_dir.join(".account-setup.json");
        let bytes = std::fs::read(&journal).unwrap();
        if !recorded {
            std::fs::remove_file(account_dir.join("account.json")).unwrap();
        }

        let promoted = if external {
            home.add_external_signer_for_setup(&public_key)
        } else {
            home.add_public_account_for_setup(&public_key)
        }
        .unwrap();

        assert_eq!(promoted.external_signing, external);
        assert_eq!(promoted.account_id_hex, previous.account_id_hex);
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(home.account_setup_state(&public_key).unwrap(), Some(state));
        assert_eq!(home.accounts().unwrap(), [promoted]);
    }
}

#[test]
fn setup_mismatch_keeps_record() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = nostr::prelude::Keys::generate().public_key().to_hex();
    let previous = home.add_public_account(&public_key).unwrap();
    let journal = home.account_dir(&public_key).join(".account-setup.json");
    let bytes = serde_json::to_vec(&AccountSetupState {
        account_id_hex: nostr::prelude::Keys::generate().public_key().to_hex(),
        reused_account_id_credential: false,
        kind: AccountSetupKind::PublicIdentity,
        phase: AccountSetupPhase::LocalReady,
    })
    .unwrap();
    std::fs::write(&journal, &bytes).unwrap();

    assert!(matches!(
        home.add_external_signer_for_setup(&public_key),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    assert_eq!(home.account(&public_key).unwrap(), previous);
    assert_eq!(std::fs::read(journal).unwrap(), bytes);
}

#[test]
fn external_db_key_restore() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let secret = home
        .external_database_secret(&account.label, ExternalSecretMode::Create)
        .unwrap();
    assert_ne!(&*secret, user.secret_key().as_secret_bytes());
    assert_eq!(home.accounts().unwrap(), vec![account.clone()]);
    assert!(matches!(
        home.load_signing_keys(&account.label),
        Err(AccountHomeError::SecretNotFound(_))
    ));
    assert!(
        !home
            .account_dir(&account.label)
            .join(marmot_account::EXTERNAL_SQLCIPHER_SECRET_FILE)
            .exists()
    );
    let reopened =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    assert_eq!(
        *reopened
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        *secret
    );
    store.keys.lock().unwrap().clear();
    assert!(matches!(
        reopened.external_database_secret(&account.label, ExternalSecretMode::Existing),
        Err(AccountHomeError::SecretNotFound(_))
    ));
    let writer = fs_private::try_acquire_private_exclusive_file_lease(
        &dir.path().join(".account-mutation.lock"),
    )
    .unwrap();
    assert!(
        matches!(reopened.external_database_secret(&account.label, ExternalSecretMode::Create),
        Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    drop(writer);
    let replacement = reopened
        .external_database_secret(&account.label, ExternalSecretMode::Create)
        .unwrap();
    assert_ne!(*replacement, *secret);
    assert_eq!(
        *reopened
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        *replacement
    );
    reopened.remove_account(&account.label).unwrap();
    assert!(store.keys.lock().unwrap().is_empty());
}

fn nip46_record(user: &nostr::prelude::Keys, client: &nostr::prelude::Keys) -> Nip46SessionRecord {
    Nip46SessionRecord {
        version: 1,
        user_public_key: user.public_key().to_hex(),
        remote_signer_public_key: nostr::prelude::Keys::generate().public_key().to_hex(),
        client_public_key: client.public_key().to_hex(),
        relays: vec!["wss://signer.example".into()],
        name: "Marmot".into(),
        permission_version: 1,
        permissions: vec!["get_public_key".into(), "sign_event:443".into()],
    }
}

#[test]
fn nip46_secret_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let home = AccountHome::open(dir.path());
    let local = home
        .import_account("local-user", &user.secret_key().to_secret_hex())
        .unwrap();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let record = nip46_record(&user, &client);
    assert!(home.load_nip46_session(&account.label).unwrap().is_none());
    let database = home
        .external_database_secret(&account.label, ExternalSecretMode::Create)
        .unwrap();
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let metadata = home.account_dir(&account.label).join(".nip46-session.json");
    let raw = std::fs::read_to_string(&metadata).unwrap();
    assert!(!raw.contains(&client.secret_key().to_secret_hex()));
    assert!(!raw.contains(&user.secret_key().to_secret_hex()));
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(json["client_public_key"], client.public_key().to_hex());
    assert_eq!(
        json["permissions"],
        serde_json::json!(["get_public_key", "sign_event:443"])
    );
    assert!(json.get("secret_key_hex").is_none());
    assert!(json.get("uri").is_none());
    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(&metadata).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(home.account_dir(&account.label))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let receipts = file_receipts(dir.path());
        assert_eq!(receipts.len(), 3, "signing, database and NIP-46 receipts");
        for secret in receipts {
            assert_eq!(
                std::fs::metadata(secret).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    drop(home);
    let reopened = AccountHome::open(dir.path());
    let (restored, metadata_record) = reopened
        .load_nip46_session(&account.label)
        .unwrap()
        .unwrap();
    assert_eq!(restored.secret_key(), client.secret_key());
    assert_eq!(metadata_record, record);
    assert_ne!(&*database, client.secret_key().as_secret_bytes());
    assert!(matches!(
        reopened.load_signing_keys(&account.label),
        Err(AccountHomeError::SecretNotFound(_))
    ));
    reopened
        .remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    reopened
        .remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert!(
        reopened
            .load_nip46_session(&account.label)
            .unwrap()
            .is_none()
    );
    assert!(
        !dir.path()
            .join("accounts/.nip46-client")
            .join(&account.label)
            .join("secret.json")
            .exists()
    );
    assert_eq!(
        reopened
            .load_signing_keys(&local.label)
            .unwrap()
            .secret_key(),
        user.secret_key()
    );
    assert_eq!(
        *reopened
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        *database
    );
    reopened
        .store_nip46_session(&account.label, &client, &record)
        .unwrap();
    reopened.remove_account(&account.label).unwrap();
    assert!(!metadata.exists());
    assert!(
        !dir.path()
            .join("accounts/.nip46-client")
            .join(&account.label)
            .join("secret.json")
            .exists()
    );
    assert_eq!(
        reopened
            .load_signing_keys(&local.label)
            .unwrap()
            .secret_key(),
        user.secret_key()
    );
}

#[test]
fn nip46_interrupted_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let record = nip46_record(&user, &client);
    store.interrupt_after_write.store(true, Ordering::SeqCst);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        home.store_nip46_session(&account.label, &client, &record)
            .unwrap();
    }));
    assert!(interrupted.is_err());
    let reopened =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let (restored, metadata) = reopened
        .load_nip46_session(&account.label)
        .unwrap()
        .expect("completed vault write must remain discoverable");
    assert_eq!(restored.secret_key(), client.secret_key());
    assert_eq!(metadata, record);
    reopened
        .remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert!(store.keys.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn nip46_atomic_metadata() {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let mut record = nip46_record(&user, &client);
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let mut reader =
        std::fs::File::open(home.account_dir(&account.label).join(".nip46-session.json")).unwrap();
    record.name = "Updated".into();
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let mut old = String::new();
    reader.read_to_string(&mut old).unwrap();
    assert_eq!(
        serde_json::from_str::<Nip46SessionRecord>(&old)
            .unwrap()
            .name,
        "Marmot"
    );
    assert_eq!(
        home.load_nip46_session(&account.label)
            .unwrap()
            .unwrap()
            .1
            .name,
        "Updated"
    );
}

#[test]
fn nip46_metadata_only_repair() {
    for replace_pairing in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemorySecretStore::default());
        let home =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        let user = nostr::prelude::Keys::generate();
        let client = nostr::prelude::Keys::generate();
        let account = home
            .add_external_signer_account(&user.public_key().to_hex())
            .unwrap();
        let record = nip46_record(&user, &client);
        store.interrupt_before_write.store(true, Ordering::SeqCst);
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            home.store_nip46_session(&account.label, &client, &record)
                .unwrap();
        }));
        assert!(interrupted.is_err());
        drop(home);
        store.interrupt_before_write.store(false, Ordering::SeqCst);
        let reopened =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        assert!(matches!(
            reopened.load_nip46_session(&account.label),
            Err(AccountHomeError::SecretNotFound(_))
        ));
        assert!(store.keys.lock().unwrap().is_empty());
        let path = reopened
            .account_dir(&account.label)
            .join(".nip46-session.json");
        let before = std::fs::read(&path).unwrap();
        let (supplied, pairing) = if replace_pairing {
            let supplied = nostr::prelude::Keys::generate();
            let pairing = nip46_record(&user, &supplied);
            (supplied, pairing)
        } else {
            (client, record)
        };
        *store.load_error.lock().unwrap() = Some(AccountHomeError::SecretStore(
            "injected locked vault".into(),
        ));
        assert!(matches!(
            reopened.store_nip46_session(&account.label, &supplied, &pairing),
            Err(AccountHomeError::SecretStore(_))
        ));
        assert!(store.keys.lock().unwrap().is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        reopened
            .store_nip46_session(&account.label, &supplied, &pairing)
            .unwrap();
        drop(reopened);
        let restored_home =
            AccountHome::open_with_secret_store(dir.path(), store, IosOptions::default());
        let (restored, metadata) = restored_home
            .load_nip46_session(&account.label)
            .unwrap()
            .unwrap();
        assert_eq!(restored.secret_key(), supplied.secret_key());
        assert_eq!(metadata, pairing);
    }
}

#[test]
fn nip46_false_absence_guard() {
    enum CredentialState {
        Present,
        Locked,
        Unavailable,
        Malformed,
    }

    for state in [
        CredentialState::Present,
        CredentialState::Locked,
        CredentialState::Unavailable,
        CredentialState::Malformed,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemorySecretStore::default());
        let home =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        let user = nostr::prelude::Keys::generate();
        let client = nostr::prelude::Keys::generate();
        let account = home
            .add_external_signer_account(&user.public_key().to_hex())
            .unwrap();
        let record = nip46_record(&user, &client);
        home.store_nip46_session(&account.label, &client, &record)
            .unwrap();
        let path = home.account_dir(&account.label).join(".nip46-session.json");
        let before = std::fs::read(&path).unwrap();
        store.hide_presence.store(true, Ordering::SeqCst);
        match state {
            CredentialState::Present => {}
            CredentialState::Locked => {
                *store.load_error.lock().unwrap() = Some(AccountHomeError::SecretStore(
                    "injected locked vault".into(),
                ));
            }
            CredentialState::Unavailable => {
                *store.load_error.lock().unwrap() = Some(AccountHomeError::SecretStoreUnavailable(
                    "injected unavailable vault".into(),
                ));
            }
            CredentialState::Malformed => {
                let label = store.keys.lock().unwrap().keys().next().unwrap().clone();
                store.keys.lock().unwrap().insert(label, "not-a-key".into());
            }
        }
        let secrets_before = store.keys.lock().unwrap().clone();
        let replacement = nostr::prelude::Keys::generate();
        let pairing = nip46_record(&user, &replacement);
        let result = home.store_nip46_session(&account.label, &replacement, &pairing);
        match state {
            CredentialState::Present => {
                assert!(matches!(result, Err(AccountHomeError::AccountIdMismatch)));
            }
            CredentialState::Locked => {
                assert!(matches!(result, Err(AccountHomeError::SecretStore(_))));
            }
            CredentialState::Unavailable => {
                assert!(matches!(
                    result,
                    Err(AccountHomeError::SecretStoreUnavailable(_))
                ));
            }
            CredentialState::Malformed => {
                assert!(matches!(result, Err(AccountHomeError::InvalidSecretKey)));
            }
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(*store.keys.lock().unwrap(), secrets_before);
        drop(home);
        let reopened =
            AccountHome::open_with_secret_store(dir.path(), store, IosOptions::default());
        if matches!(state, CredentialState::Malformed) {
            assert!(matches!(
                reopened.load_nip46_session(&account.label),
                Err(AccountHomeError::InvalidSecretKey)
            ));
        } else {
            let (restored, metadata) = reopened
                .load_nip46_session(&account.label)
                .unwrap()
                .unwrap();
            assert_eq!(restored.secret_key(), client.secret_key());
            assert_eq!(metadata, record);
        }
    }
}

#[test]
fn nip46_keychain_isolation() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let service = format!("mdk-nip46-{}", dir.path().display());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let home =
        AccountHome::open_with_keychain(dir.path(), &service, IosOptions::default()).unwrap();
    let local = home
        .import_account("local-user", &user.secret_key().to_secret_hex())
        .unwrap();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let database = home
        .external_database_secret(&account.label, ExternalSecretMode::Create)
        .unwrap();
    home.store_nip46_session(&account.label, &client, &nip46_record(&user, &client))
        .unwrap();
    drop(home);
    let reopened =
        AccountHome::open_with_keychain(dir.path(), service, IosOptions::default()).unwrap();
    assert_eq!(
        reopened
            .load_nip46_session(&account.label)
            .unwrap()
            .unwrap()
            .0
            .secret_key(),
        client.secret_key()
    );
    assert!(
        !reopened
            .account_dir(&account.label)
            .join("secret.json")
            .exists()
    );
    assert!(!dir.path().join("accounts/.nip46-client").exists());
    reopened
        .remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert_eq!(
        reopened
            .load_signing_keys(&local.label)
            .unwrap()
            .secret_key(),
        user.secret_key()
    );
    assert_eq!(
        *reopened
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        *database
    );
    reopened.remove_account(&account.label).unwrap();
    reopened.remove_account(&local.label).unwrap();
}

#[test]
fn nip46_metadata_remove_failure() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let record = nip46_record(&user, &client);
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let removing = home
        .account_dir(&account.label)
        .join(".nip46-session-removing.json");
    std::fs::create_dir(&removing).unwrap();
    let error = home
        .remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap_err();
    assert!(matches!(error, AccountHomeError::Io(error)
        if matches!(error.kind(), std::io::ErrorKind::IsADirectory | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AlreadyExists)));
    assert_eq!(
        store.keys.lock().unwrap().values().next().unwrap(),
        &client.secret_key().to_secret_hex()
    );
    std::fs::remove_dir(removing).unwrap();
    assert_eq!(
        home.load_nip46_session(&account.label).unwrap().unwrap().1,
        record
    );
    home.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert!(store.keys.lock().unwrap().is_empty());
}

#[test]
fn nip46_invalid_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let record = nip46_record(&user, &client);
    let other = nostr::prelude::Keys::generate();
    let mut wrong = record.clone();
    wrong.user_public_key = other.public_key().to_hex();
    assert!(matches!(
        home.store_nip46_session(&account.label, &client, &wrong),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    assert!(matches!(
        home.store_nip46_session(&account.label, &other, &record),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    let public = home
        .add_public_account(&other.public_key().to_hex())
        .unwrap();
    assert!(matches!(
        home.store_nip46_session(&public.label, &client, &record),
        Err(AccountHomeError::InvalidSecretKey)
    ));
    let local = home
        .import_account("local", &other.secret_key().to_secret_hex())
        .unwrap();
    assert!(matches!(
        home.store_nip46_session(&local.label, &client, &record),
        Err(AccountHomeError::InvalidSecretKey)
    ));
    for case in 0..9 {
        let mut invalid = record.clone();
        match case {
            0 => invalid.version = 2,
            1 => invalid.permission_version = 0,
            2 => invalid.relays.clear(),
            3 => invalid.relays = vec!["wss://relay.example".into(); 17],
            4 => invalid.relays = vec!["not-a-relay".into()],
            5 => invalid.name = "x".repeat(257),
            6 => invalid.permissions = vec!["get_public_key".into(); 65],
            7 => invalid.permissions = vec!["x".repeat(257)],
            _ => invalid.name = "bad\nname".into(),
        }
        assert!(
            matches!(home.store_nip46_session(&account.label, &client, &invalid), Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData),
            "case {case}"
        );
    }
    assert_eq!(
        store.keys.lock().unwrap().len(),
        1,
        "only the unrelated local key exists"
    );
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let replacement = nip46_record(&user, &other);
    assert!(matches!(
        home.store_nip46_session(&account.label, &other, &replacement),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    assert_eq!(
        home.load_nip46_session(&account.label)
            .unwrap()
            .unwrap()
            .0
            .secret_key(),
        client.secret_key()
    );
}

#[test]
fn nip46_corrupt_storage() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let record = nip46_record(&user, &client);
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let credential_label = store.keys.lock().unwrap().keys().next().unwrap().clone();
    store
        .keys
        .lock()
        .unwrap()
        .insert(credential_label.clone(), user.secret_key().to_secret_hex());
    assert!(matches!(
        home.load_nip46_session(&account.label),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    store.hide_presence.store(true, Ordering::SeqCst);
    assert!(matches!(
        home.store_nip46_session(&account.label, &client, &record),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    assert_eq!(
        store.keys.lock().unwrap()[&credential_label],
        user.secret_key().to_secret_hex()
    );
    store.keys.lock().unwrap().remove(&credential_label);
    assert!(matches!(
        home.load_nip46_session(&account.label),
        Err(AccountHomeError::SecretNotFound(_))
    ));
    let path = home.account_dir(&account.label).join(".nip46-session.json");
    std::fs::write(&path, "{").unwrap();
    assert!(matches!(
        home.load_nip46_session(&account.label),
        Err(AccountHomeError::Json(_))
    ));
    assert!(matches!(
        home.store_nip46_session(&account.label, &client, &record),
        Err(AccountHomeError::Json(_))
    ));
    std::fs::write(&path, vec![b' '; 128 * 1024 + 1]).unwrap();
    assert!(
        matches!(home.load_nip46_session(&account.label), Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    assert!(
        matches!(home.store_nip46_session(&account.label, &client, &record), Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    home.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert!(home.load_nip46_session(&account.label).unwrap().is_none());
}

#[test]
fn nip55_logout_without_pairing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    home.external_database_secret(&account.label, ExternalSecretMode::Create)
        .unwrap();
    let database_label = store.keys.lock().unwrap().keys().next().unwrap().clone();
    let database_secret = store.keys.lock().unwrap()[&database_label].clone();
    store.fail_lookup.store(true, Ordering::SeqCst);
    home.set_account_signed_out(&account.label, true).unwrap();
    home.remove_nip46_session(&account.label, Nip46Removal::Recorded)
        .unwrap();
    assert!(home.account(&account.label).unwrap().signed_out);
    assert_eq!(store.keys.lock().unwrap()[&database_label], database_secret);
}

#[test]
fn wipe_without_nip46_vault() {
    for signing in [0, 1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemorySecretStore::default());
        let home =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        let user = nostr::prelude::Keys::generate();
        let account = match signing {
            0 => home.add_public_account(&user.public_key().to_hex()),
            1 => home.add_external_signer_account(&user.public_key().to_hex()),
            _ => home.import_account("local", &user.secret_key().to_secret_hex()),
        }
        .unwrap();
        if account.external_signing {
            home.external_database_secret(&account.label, ExternalSecretMode::Create)
                .unwrap();
        }
        drop(home);
        let reopened =
            AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
        store.fail_lookup.store(true, Ordering::SeqCst);
        store.fail_namespace.store(signing == 0, Ordering::SeqCst);
        reopened.remove_account(&account.label).unwrap();
        assert!(reopened.accounts_strict().unwrap().is_empty());
        assert!(!reopened.account_dir(&account.label).exists());
        assert!(store.keys.lock().unwrap().is_empty());
    }
}

#[test]
fn public_wipe_skips_empty_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("separate-vault");
    let home = AccountHome::open_with_secret_store(
        dir.path().join("home"),
        Arc::new(LocalFileSecretStore::new(&vault, IosOptions::default())),
        IosOptions::default(),
    );
    let label = nostr::prelude::Keys::generate().public_key().to_hex();
    let account = home.add_public_account_for_setup(&label).unwrap();
    assert!(!account.can_sign());
    home.remove_account(&label).unwrap();
    assert!(home.accounts_strict().unwrap().is_empty());
    assert!(!home.account_dir(&label).exists());
    assert!(!vault.exists());
}

fn write_legacy_external(home: &AccountHome, label: &str) {
    let account_dir = home.account_dir(label);
    fs_private::create_dir_all_private(&account_dir).unwrap();
    fs_private::write_private(
        &account_dir.join("account.json"),
        &serde_json::to_vec(&serde_json::json!({
            "label": label,
            "account_id_hex": label,
            "local_signing": false,
            "external_signing": true,
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn nip46_absent_orphan_repair() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let client = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
    let label = user.public_key().to_hex();
    write_legacy_external(&home, &label);

    home.remove_nip46_session(&label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    let record = nip46_record(&user, &client);
    assert!(matches!(
        home.store_nip46_session(&label, &client, &record).unwrap(),
        Nip46SessionWrite::Created
    ));
    drop(home);

    let reopened = AccountHome::open(dir.path());
    let (restored, restored_record) = reopened.load_nip46_session(&label).unwrap().unwrap();
    assert_eq!(restored.secret_key(), client.secret_key());
    assert_eq!(restored_record, record);
    for _ in 0..2 {
        reopened
            .remove_nip46_session(&label, Nip46Removal::IncludingOrphaned)
            .unwrap();
    }
    assert!(reopened.load_nip46_session(&label).unwrap().is_none());
}

#[test]
fn nip46_unreadable_removal() {
    #[derive(Clone, Copy)]
    enum Acquisition {
        Unclaimed,
        Pending,
    }

    for acquisition in [Acquisition::Unclaimed, Acquisition::Pending] {
        for removal in [Nip46Removal::Recorded, Nip46Removal::IncludingOrphaned] {
            let dir = tempfile::tempdir().unwrap();
            let home = AccountHome::open(dir.path());
            let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
            let old = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
            let label = user.public_key().to_hex();
            let raw = write_legacy_nip46(&home, &user, &old);
            fs_private::write_private(&raw, b"{").unwrap();
            if matches!(acquisition, Acquisition::Pending) {
                assert!(matches!(
                    home.load_nip46_session(&label),
                    Err(AccountHomeError::Json(_))
                ));
            }
            if removal == Nip46Removal::IncludingOrphaned {
                std::fs::remove_file(home.account_dir(&label).join(".nip46-session.json")).unwrap();
            }
            home.remove_nip46_session(&label, removal).unwrap();
            assert!(home.load_nip46_session(&label).unwrap().is_none());
            assert_eq!(std::fs::read(&raw).unwrap(), b"{");
            let fresh = nostr::prelude::Keys::parse(&"03".repeat(32)).unwrap();
            let record = nip46_record(&user, &fresh);
            drop(home);

            let reopened = AccountHome::open(dir.path());
            reopened.remove_nip46_session(&label, removal).unwrap();
            assert!(reopened.load_nip46_session(&label).unwrap().is_none());
            reopened
                .store_nip46_session(&label, &fresh, &record)
                .unwrap();
            assert_eq!(
                reopened
                    .load_nip46_session(&label)
                    .unwrap()
                    .unwrap()
                    .0
                    .secret_key(),
                fresh.secret_key()
            );
            assert_eq!(std::fs::read(&raw).unwrap(), b"{");
        }
    }
}

fn write_legacy_nip46(
    home: &AccountHome,
    user: &nostr::prelude::Keys,
    client: &nostr::prelude::Keys,
) -> std::path::PathBuf {
    let label = user.public_key().to_hex();
    write_legacy_external(home, &label);
    let raw = write_raw_nip46(home, &label, client);
    fs_private::write_private(
        &home.account_dir(&label).join(".nip46-session.json"),
        &serde_json::to_vec(&nip46_record(user, client)).unwrap(),
    )
    .unwrap();
    raw
}

fn write_raw_nip46(
    home: &AccountHome,
    label: &str,
    client: &nostr::prelude::Keys,
) -> std::path::PathBuf {
    let directory = home.root().join("accounts/.nip46-client").join(label);
    fs_private::create_dir_all_private(&directory).unwrap();
    let raw = directory.join("secret.json");
    fs_private::write_private(
        &raw,
        &serde_json::to_vec(
            &serde_json::json!({"secret_key_hex": client.secret_key().to_secret_hex()}),
        )
        .unwrap(),
    )
    .unwrap();
    raw
}

#[test]
fn nip46_legacy_removal_repair() {
    #[derive(Clone, Copy)]
    enum Migration {
        Unmigrated,
        Known,
        Unknown,
    }

    for migration in [Migration::Unmigrated, Migration::Known, Migration::Unknown] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
        let old = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
        let label = user.public_key().to_hex();
        let raw = write_legacy_nip46(&home, &user, &old);
        let raw_bytes = std::fs::read(&raw).unwrap();
        if !matches!(migration, Migration::Unmigrated) {
            assert_eq!(
                home.load_nip46_session(&label)
                    .unwrap()
                    .unwrap()
                    .0
                    .secret_key(),
                old.secret_key()
            );
        }
        if matches!(migration, Migration::Unknown) {
            // A migrated raw search can have no provable original scope.
            let receipt = file_receipts(dir.path()).pop().unwrap();
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
            value["legacy"]["origin_scope"] = serde_json::Value::Null;
            fs_private::write_private(&receipt, &serde_json::to_vec(&value).unwrap()).unwrap();
        }
        home.remove_nip46_session(&label, Nip46Removal::Recorded)
            .unwrap();
        assert!(home.load_nip46_session(&label).unwrap().is_none());
        home.remove_nip46_session(&label, Nip46Removal::IncludingOrphaned)
            .unwrap();
        drop(home);

        for byte in ["03", "04"] {
            let home = AccountHome::open(dir.path());
            let fresh = nostr::prelude::Keys::parse(&byte.repeat(32)).unwrap();
            let record = nip46_record(&user, &fresh);
            assert!(matches!(
                home.store_nip46_session(&label, &fresh, &record).unwrap(),
                Nip46SessionWrite::Created
            ));
            drop(home);
            let reopened = AccountHome::open(dir.path());
            let (keys, restored) = reopened.load_nip46_session(&label).unwrap().unwrap();
            assert_eq!(keys.secret_key(), fresh.secret_key());
            assert_eq!(restored, record);
            reopened
                .remove_nip46_session(&label, Nip46Removal::Recorded)
                .unwrap();
            assert!(reopened.load_nip46_session(&label).unwrap().is_none());
        }
        assert_eq!(std::fs::read(raw).unwrap(), raw_bytes);
    }
}

#[test]
fn nip46_orphaned_key_removal() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    home.store_nip46_session(&account.label, &client, &nip46_record(&user, &client))
        .unwrap();
    std::fs::remove_file(home.account_dir(&account.label).join(".nip46-session.json")).unwrap();
    store.hide_presence.store(true, Ordering::SeqCst);
    let label = store.keys.lock().unwrap().keys().next().unwrap().clone();
    home.remove_nip46_session(&account.label, Nip46Removal::Recorded)
        .unwrap();
    assert_eq!(
        store.keys.lock().unwrap()[&label],
        client.secret_key().to_secret_hex()
    );
    store.fail_remove.store(true, Ordering::SeqCst);
    assert!(matches!(
        home.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned),
        Err(AccountHomeError::SecretStore(_))
    ));
    assert!(
        matches!(home.load_nip46_session(&account.label), Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    store.fail_remove.store(false, Ordering::SeqCst);
    home.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert!(!store.keys.lock().unwrap().contains_key(&label));
    assert_eq!(home.account(&account.label).unwrap(), account);
}

#[test]
fn nip46_interrupted_repair() {
    #[derive(Clone, Copy)]
    enum Interruption {
        BeforeWrite,
        AfterWrite,
        MissingClaim,
    }
    #[derive(Clone, Copy)]
    enum Recovery {
        LoadThenRetry,
        Retry,
        RemoveThenPair,
    }

    for interruption in [
        Interruption::BeforeWrite,
        Interruption::AfterWrite,
        Interruption::MissingClaim,
    ] {
        for recovery in [
            Recovery::LoadThenRetry,
            Recovery::Retry,
            Recovery::RemoveThenPair,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(FaultAcquireStore {
                inner: LocalFileSecretStore::new(dir.path(), IosOptions::default()),
                fault: Mutex::new(None),
            });
            let home = AccountHome::open_with_secret_store(
                dir.path(),
                store.clone(),
                IosOptions::default(),
            );
            let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
            let old = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
            let fresh = nostr::prelude::Keys::parse(&"03".repeat(32)).unwrap();
            let label = user.public_key().to_hex();
            let raw = write_legacy_nip46(&home, &user, &old);
            let raw_bytes = std::fs::read(&raw).unwrap();
            home.load_nip46_session(&label).unwrap().unwrap();
            home.remove_nip46_session(&label, Nip46Removal::Recorded)
                .unwrap();
            *store.fault.lock().unwrap() =
                Some(if matches!(interruption, Interruption::AfterWrite) {
                    AcquireFault::AfterWrite
                } else {
                    AcquireFault::BeforeWrite
                });
            let record = nip46_record(&user, &fresh);
            assert!(matches!(
                home.store_nip46_session(&label, &fresh, &record),
                Err(AccountHomeError::SecretStore(message)) if message.starts_with("injected unavailable vault ")
            ));
            if matches!(interruption, Interruption::MissingClaim) {
                // Process death between clearing the retired reference and saving the new claim.
                let path = home.account_dir(&label).join(".credential-ownership.json");
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value["credentials"][2] = serde_json::Value::Null;
                fs_private::write_private(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
            }
            drop(home);
            let reopened = AccountHome::open_with_secret_store(
                dir.path(),
                store.clone(),
                IosOptions::default(),
            );
            match recovery {
                Recovery::LoadThenRetry => {
                    if matches!(interruption, Interruption::AfterWrite) {
                        let (keys, restored) =
                            reopened.load_nip46_session(&label).unwrap().unwrap();
                        assert_eq!(keys.secret_key(), fresh.secret_key());
                        assert_eq!(restored, record);
                    } else {
                        assert!(matches!(
                            reopened.load_nip46_session(&label),
                            Err(AccountHomeError::SecretNotFound(_))
                        ));
                    }
                }
                Recovery::Retry => {}
                Recovery::RemoveThenPair => {
                    reopened
                        .remove_nip46_session(&label, Nip46Removal::Recorded)
                        .unwrap();
                    assert!(reopened.load_nip46_session(&label).unwrap().is_none());
                }
            }
            let outcome = reopened
                .store_nip46_session(&label, &fresh, &record)
                .unwrap();
            if matches!(recovery, Recovery::RemoveThenPair) {
                assert!(matches!(outcome, Nip46SessionWrite::Created), "{outcome:?}");
            }
            drop(reopened);
            let loaded =
                AccountHome::open_with_secret_store(dir.path(), store, IosOptions::default());
            let (keys, restored) = loaded.load_nip46_session(&label).unwrap().unwrap();
            assert_eq!(keys.secret_key(), fresh.secret_key());
            assert_eq!(restored, record);
            assert_eq!(std::fs::read(&raw).unwrap(), raw_bytes);
        }
    }
}

#[test]
fn nip46_orphan_wipe_intent() {
    #[derive(Clone, Copy)]
    enum Undo {
        None,
        Paired,
        Legacy,
    }

    let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let old = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
    let fresh = nostr::prelude::Keys::parse(&"03".repeat(32)).unwrap();
    let label = user.public_key().to_hex();
    for undo in [Undo::None, Undo::Paired, Undo::Legacy] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let raw = write_legacy_nip46(&home, &user, &old);
        let raw_bytes = std::fs::read(&raw).unwrap();
        std::fs::remove_file(home.account_dir(&label).join(".nip46-session.json")).unwrap();
        if !matches!(undo, Undo::Legacy) {
            home.store_nip46_session(&label, &fresh, &nip46_record(&user, &fresh))
                .unwrap();
        }
        drop(home);
        let home = AccountHome::open(dir.path());
        let home = if !matches!(undo, Undo::None) {
            home.revert_external_signer_upgrade(&label).unwrap();
            assert!(!home.account(&label).unwrap().can_sign());
            assert!(file_receipts(dir.path()).is_empty());
            if matches!(undo, Undo::Legacy) {
                let history: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(home.account_dir(&label).join(".credential-ownership.json"))
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(history["account"]["external_signing"], true);
            }
            drop(home);
            AccountHome::open(dir.path())
        } else {
            home
        };
        home.remove_account(&label).unwrap();
        assert!(home.accounts_strict().unwrap().is_empty());
        assert!(!home.account_dir(&label).exists());
        assert!(file_receipts(dir.path()).is_empty());
        assert_eq!(std::fs::read(&raw).unwrap(), raw_bytes);
        let tombstone = std::fs::read_dir(dir.path().join(".wipe-tombstones"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let intent: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tombstone.join(".wipe-cleanup.json")).unwrap())
                .unwrap();
        let target: AccountSummary =
            serde_json::from_value(intent["legacy"][2]["account"].clone()).unwrap();
        let kind: SecretCredentialKind =
            serde_json::from_value(intent["legacy"][2]["kind"].clone()).unwrap();
        assert_eq!(kind, SecretCredentialKind::Nip46Session);
        assert_eq!(
            dir.path()
                .join("accounts")
                .join(target.label)
                .join("secret.json"),
            raw
        );
        home.resume_wipe_cleanup().unwrap();
        assert_eq!(std::fs::read(&raw).unwrap(), raw_bytes);
        assert!(tombstone.join(".wipe-cleanup.json").exists());
    }
}

#[test]
fn nip46_retirement_retry() {
    let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let old = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
    let fresh = nostr::prelude::Keys::parse(&"03".repeat(32)).unwrap();
    let label = user.public_key().to_hex();
    let pairing = nip46_record(&user, &fresh);
    for reverted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let public = home.add_public_account(&label).unwrap();
        let path = home.account_dir(&label);
        let payload = path.join("session.sqlite");
        std::fs::write(&payload, b"original public payload").unwrap();
        let external = home.add_external_signer_account(&label).unwrap();
        let raw = write_raw_nip46(&home, &label, &user);
        let raw_bytes = std::fs::read(&raw).unwrap();
        assert!(matches!(
            home.store_nip46_session(&label, &old, &nip46_record(&user, &old)),
            Ok(Nip46SessionWrite::Created)
        ));
        let old_receipt = file_receipts(dir.path()).pop().unwrap();
        let old_receipt_bytes = std::fs::read(&old_receipt).unwrap();
        let locked = fs_private::try_acquire_private_exclusive_file_lease(
            &dir.path().join(".credential-store.lock"),
        )
        .unwrap();

        if reverted {
            home.revert_external_signer_upgrade(&label).unwrap();
            assert_eq!(home.account(&label).unwrap(), public);
            assert!(home.load_nip46_session(&label).unwrap().is_none());
        } else {
            assert!(matches!(
                home.remove_nip46_session(&label, Nip46Removal::Recorded),
                Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
        }
        drop(home);

        let reopened = AccountHome::open(dir.path());
        if reverted {
            assert!(matches!(
                reopened.add_external_signer_for_setup(&label),
                Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            assert_eq!(reopened.accounts_strict().unwrap(), [public]);
            assert!(reopened.account_setup_state(&label).unwrap().is_none());
        } else {
            assert!(matches!(
                reopened.store_nip46_session(&label, &fresh, &pairing),
                Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            assert_eq!(reopened.account(&label).unwrap(), external);
        }
        let removing = path.join(".nip46-session-removing.json");
        assert!(removing.is_file());
        assert!(!path.join(".nip46-session.json").exists());
        assert_eq!(
            file_receipts(dir.path()).as_slice(),
            std::slice::from_ref(&old_receipt)
        );
        assert_eq!(std::fs::read(&old_receipt).unwrap(), old_receipt_bytes);
        drop(locked);

        if reverted {
            assert_eq!(
                reopened.add_external_signer_for_setup(&label).unwrap(),
                external
            );
            assert!(!old_receipt.exists());
            assert!(reopened.load_nip46_session(&label).unwrap().is_none());
        }
        assert!(matches!(
            reopened.store_nip46_session(&label, &fresh, &pairing),
            Ok(Nip46SessionWrite::Created)
        ));
        assert!(!old_receipt.exists());
        assert!(!removing.exists());
        assert_eq!(file_receipts(dir.path()).len(), 1);
        drop(reopened);

        let paired = AccountHome::open(dir.path());
        let (keys, record) = paired.load_nip46_session(&label).unwrap().unwrap();
        assert_eq!(keys.secret_key(), fresh.secret_key());
        assert_eq!(record, pairing);
        assert_eq!(std::fs::read(&payload).unwrap(), b"original public payload");
        assert_eq!(std::fs::read(&raw).unwrap(), raw_bytes);
    }
}

#[test]
fn nip46_storage_failure_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::generate();
    let client = nostr::prelude::Keys::generate();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let record = nip46_record(&user, &client);
    store.fail_remove.store(true, Ordering::SeqCst);
    home.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert_eq!(home.account(&account.label).unwrap(), account);
    store.fail_remove.store(false, Ordering::SeqCst);
    store.fail_write.store(true, Ordering::SeqCst);
    assert!(matches!(
        home.store_nip46_session(&account.label, &client, &record),
        Err(AccountHomeError::SecretStore(_))
    ));
    assert!(store.keys.lock().unwrap().is_empty());
    assert!(matches!(
        home.load_nip46_session(&account.label),
        Err(AccountHomeError::SecretNotFound(_))
    ));
    store.fail_write.store(false, Ordering::SeqCst);
    home.store_nip46_session(&account.label, &client, &record)
        .unwrap();
    let database = home
        .external_database_secret(&account.label, ExternalSecretMode::Create)
        .unwrap();
    store.fail_remove.store(true, Ordering::SeqCst);
    assert!(matches!(
        home.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned),
        Err(AccountHomeError::SecretStore(_))
    ));
    assert_eq!(home.account(&account.label).unwrap(), account);
    assert!(!dir.path().join(".wipe-tombstones").exists());
    assert_eq!(store.keys.lock().unwrap().len(), 2);
    assert_eq!(
        *home
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        *database
    );
    let reopened =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    assert!(
        matches!(reopened.load_nip46_session(&account.label), Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    store.fail_remove.store(false, Ordering::SeqCst);
    reopened
        .remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned)
        .unwrap();
    assert!(
        reopened
            .load_nip46_session(&account.label)
            .unwrap()
            .is_none()
    );
    assert_eq!(store.keys.lock().unwrap().len(), 1);
    reopened
        .store_nip46_session(&account.label, &client, &record)
        .unwrap();
    store.fail_remove_after_delete.store(true, Ordering::SeqCst);
    assert!(matches!(
        reopened.remove_nip46_session(&account.label, Nip46Removal::IncludingOrphaned),
        Err(AccountHomeError::SecretStore(_))
    ));
    assert!(
        !reopened
            .account_dir(&account.label)
            .join(".nip46-session.json")
            .exists()
    );
    assert_eq!(
        store.keys.lock().unwrap().len(),
        1,
        "only the database credential remains"
    );
    assert!(
        matches!(reopened.load_nip46_session(&account.label), Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    store
        .fail_remove_after_delete
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        reopened.store_nip46_session(&account.label, &client, &record),
        Ok(Nip46SessionWrite::Created)
    ));
    reopened.remove_account(&account.label).unwrap();
    assert!(store.keys.lock().unwrap().is_empty());
}

#[test]
fn external_db_key_migration() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    let legacy = home
        .account_dir(&account.label)
        .join(marmot_account::EXTERNAL_SQLCIPHER_SECRET_FILE);
    std::fs::write(&legacy, "02".repeat(32)).unwrap();
    assert_eq!(
        *home
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        [2; 32]
    );
    assert!(!legacy.exists());
    let reopened = AccountHome::open_with_secret_store(dir.path(), store, IosOptions::default());
    assert_eq!(
        *reopened
            .external_database_secret(&account.label, ExternalSecretMode::Existing)
            .unwrap(),
        [2; 32]
    );
}

#[test]
fn external_db_key_missing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let user = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let account = home
        .add_external_signer_account(&user.public_key().to_hex())
        .unwrap();
    assert!(matches!(
        home.external_database_secret(&account.label, ExternalSecretMode::Existing),
        Err(AccountHomeError::SecretNotFound(_))
    ));
    assert!(store.keys.lock().unwrap().is_empty());
}

#[test]
fn account_home_rejects_external_signer_upgrade_for_local_identity() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account().unwrap();

    assert!(matches!(
        home.add_external_signer_account(&account.account_id_hex),
        Err(AccountHomeError::AccountExists(existing)) if existing == account.account_id_hex
    ));
    assert!(matches!(
        home.add_external_signer_for_setup(&account.account_id_hex),
        Err(AccountHomeError::AccountExists(existing)) if existing == account.account_id_hex
    ));
    assert_eq!(home.account(&account.label).unwrap(), account);
    assert!(home.account_setup_state(&account.label).unwrap().is_none());
}

#[test]
fn account_home_can_use_an_injected_secret_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());

    let created = home.create_nostr_account().unwrap();

    assert!(
        !dir.path()
            .join("accounts")
            .join(&created.account_id_hex)
            .join("secret.json")
            .exists()
    );
    let reopened = AccountHome::open_with_secret_store(dir.path(), store, IosOptions::default());
    assert_eq!(
        reopened
            .load_signing_keys(&created.account_id_hex)
            .unwrap()
            .public_key()
            .to_hex(),
        created.account_id_hex
    );
}

#[test]
fn account_home_persists_reversible_sign_out_marker() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    let created = home.create_nostr_account().unwrap();
    assert!(!created.signed_out);
    assert!(created.is_active_local_signing());

    let signed_out = home
        .set_account_signed_out(&created.account_id_hex, true)
        .unwrap();
    assert!(signed_out.signed_out);
    assert!(!signed_out.is_active_local_signing());

    let reopened = AccountHome::open(dir.path());
    let persisted = reopened.account(&created.account_id_hex).unwrap();
    assert!(persisted.signed_out);
    assert!(!persisted.is_active_local_signing());
    assert_eq!(
        reopened
            .load_signing_keys(&created.account_id_hex)
            .unwrap()
            .public_key()
            .to_hex(),
        created.account_id_hex
    );

    let reactivated = reopened
        .set_account_signed_out(&created.account_id_hex, false)
        .unwrap();
    assert!(!reactivated.signed_out);
    assert!(reactivated.is_active_local_signing());
}

#[test]
fn account_home_persists_reversible_external_signer_sign_out_marker() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = nostr::prelude::Keys::generate().public_key().to_hex();

    let created = home.add_external_signer_account(&public_key).unwrap();
    assert!(created.external_signing);
    assert!(!created.signed_out);
    assert!(created.is_active_signing());

    let signed_out = home
        .set_account_signed_out(&created.account_id_hex, true)
        .unwrap();
    assert!(signed_out.signed_out);
    assert!(!signed_out.is_active_signing());

    let reactivated = home
        .set_account_signed_out(&created.account_id_hex, false)
        .unwrap();
    assert!(!reactivated.signed_out);
    assert!(reactivated.is_active_signing());
}

#[test]
fn account_home_deserializes_legacy_account_records_as_signed_in() {
    let account_id_hex = "00".repeat(32);
    let legacy = serde_json::json!({
        "label": "alice",
        "account_id_hex": account_id_hex,
        "local_signing": true,
    });

    let account: AccountSummary = serde_json::from_value(legacy).unwrap();
    assert!(!account.signed_out);
    assert!(account.is_active_local_signing());
}

#[test]
fn account_home_keychain_rejects_second_label_for_same_account_id() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open_with_keychain(
        dir.path(),
        "com.marmot.test.dup-guard",
        IosOptions::default(),
    )
    .unwrap();
    let secret_hex = nostr::prelude::Keys::generate()
        .secret_key()
        .to_secret_hex();

    home.import_account("label-one", &secret_hex).unwrap();

    assert!(matches!(
        home.import_account("label-two", &secret_hex),
        Err(AccountHomeError::AccountIdInUse(_))
    ));
}

#[test]
fn account_home_idempotent_import_recovers_orphaned_keychain_credential() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open_with_keychain(
        dir.path(),
        "com.marmot.test.orphan-recovery",
        IosOptions::default(),
    )
    .unwrap();
    let keys = nostr::prelude::Keys::generate();
    let secret_hex = keys.secret_key().to_secret_hex();
    let original = home.import_account("old-label", &secret_hex).unwrap();
    std::fs::remove_dir_all(home.account_dir(&original.label)).unwrap();
    assert!(home.accounts().unwrap().is_empty());

    let recovered = home
        .import_account_idempotent("agent", &secret_hex)
        .unwrap();

    assert_eq!(recovered.label, "agent");
    assert_eq!(recovered.account_id_hex, original.account_id_hex);
    assert_eq!(
        home.load_signing_keys("agent").unwrap().public_key(),
        keys.public_key()
    );
}

#[test]
fn account_home_runtime_import_does_not_capture_mismatched_keychain_credential() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let requested_keys = nostr::prelude::Keys::generate();
    let unrelated_keys = nostr::prelude::Keys::generate();
    let account_id = requested_keys.public_key().to_hex();
    let service = format!("com.marmot.test.runtime-mismatch-{account_id}");
    let legacy = keyring_core::Entry::new(&service, &account_id).unwrap();
    legacy
        .set_password(&unrelated_keys.secret_key().to_secret_hex())
        .unwrap();
    let store = KeychainSecretStore::new(service, &IosOptions::default()).unwrap();
    let home = AccountHome::open_with_secret_store(
        dir.path(),
        Arc::new(store.clone()),
        IosOptions::default(),
    );

    assert!(matches!(
        home.import_nostr_account_idempotent(&requested_keys.secret_key().to_secret_hex()),
        Err(AccountHomeError::AccountIdMismatch)
    ));
    assert!(home.accounts().unwrap().is_empty());
    assert_eq!(
        nostr::prelude::Keys::parse(&legacy.get_password().unwrap())
            .unwrap()
            .public_key(),
        unrelated_keys.public_key()
    );
}

#[test]
fn runtime_import_resumes_only_while_durable_setup_is_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let keys = nostr::prelude::Keys::generate();
    let secret = keys.secret_key().to_secret_hex();

    let first = home.import_nostr_account_idempotent(&secret).unwrap();
    let resumed = home.import_nostr_account_idempotent(&secret).unwrap();
    assert_eq!(resumed.account(), first.account());
    assert!(
        home.account_setup_state(&first.account().label)
            .unwrap()
            .is_some()
    );

    home.complete_account_setup(&first.account().label).unwrap();
    assert!(matches!(
        home.import_nostr_account_idempotent(&secret),
        Err(AccountHomeError::AccountExists(account))
            if account == first.account().account_id_hex
    ));
}

#[test]
fn account_home_keychain_keeps_signing_secret_when_public_twin_record_is_removed() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open_with_keychain(
        dir.path(),
        "com.marmot.test.public-twin",
        IosOptions::default(),
    )
    .unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account_id = keys.public_key().to_hex();
    let secret_hex = keys.secret_key().to_secret_hex();

    home.add_public_account(&account_id).unwrap();
    home.import_account("signing", &secret_hex).unwrap();

    home.remove_account(&account_id).unwrap();
    assert_eq!(
        home.load_signing_keys("signing")
            .unwrap()
            .public_key()
            .to_hex(),
        account_id
    );

    // Removing the last signing record releases the credential, so the same
    // key can be imported again.
    home.remove_account("signing").unwrap();
    home.import_account("signing-again", &secret_hex).unwrap();
}

#[test]
fn account_home_keychain_keeps_public_twin_when_signing_record_is_removed_first() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open_with_keychain(
        dir.path(),
        "com.marmot.test.public-twin-reverse",
        IosOptions::default(),
    )
    .unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account_id = keys.public_key().to_hex();
    let secret_hex = keys.secret_key().to_secret_hex();

    home.add_public_account(&account_id).unwrap();
    home.import_account("signing", &secret_hex).unwrap();

    // Remove the signing record first; the public twin is independent and
    // must still be queryable. It carries `local_signing = false` so it
    // never reaches the keychain.
    home.remove_account("signing").unwrap();
    let twin = home.account(&account_id).unwrap();
    assert_eq!(twin.account_id_hex, account_id);
    assert!(!twin.local_signing);
    assert!(matches!(
        home.load_signing_keys(&account_id),
        Err(AccountHomeError::SecretNotFound(_))
    ));
}

#[test]
fn account_home_keychain_keeps_shared_credential_for_surviving_signing_record() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open_with_keychain(
        dir.path(),
        "com.marmot.test.legacy-twin",
        IosOptions::default(),
    )
    .unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account_id = keys.public_key().to_hex();

    let legacy = keyring_core::Entry::new("com.marmot.test.legacy-twin", &account_id).unwrap();
    legacy
        .set_password(&keys.secret_key().to_secret_hex())
        .unwrap();
    let twin = AccountSummary {
        label: "label-two".to_owned(),
        account_id_hex: account_id.clone(),
        local_signing: true,
        external_signing: false,
        signed_out: false,
        unlinked: false,
    };
    for label in ["label-one", "label-two"] {
        let account = AccountSummary {
            label: label.to_owned(),
            ..twin.clone()
        };
        let directory = home.account_dir(label);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("account.json"),
            serde_json::to_vec(&account).unwrap(),
        )
        .unwrap();
    }

    home.remove_account("label-one").unwrap();

    assert_eq!(
        home.load_signing_keys("label-two")
            .unwrap()
            .public_key()
            .to_hex(),
        account_id
    );
}

#[test]
fn account_home_file_store_keeps_per_label_secrets_for_same_account_id() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let keys = nostr::prelude::Keys::generate();
    let secret_hex = keys.secret_key().to_secret_hex();

    // Label-keyed stores hold one secret per label, so the same key may be
    // imported under two labels and each record stays independently removable.
    home.import_account("label-one", &secret_hex).unwrap();
    home.import_account("label-two", &secret_hex).unwrap();

    home.remove_account("label-one").unwrap();

    assert_eq!(
        home.load_signing_keys("label-two")
            .unwrap()
            .public_key()
            .to_hex(),
        keys.public_key().to_hex()
    );
}

#[cfg(unix)]
#[test]
fn account_home_scrubs_tombstoned_local_secret_before_failed_recursive_delete() {
    use std::io::Read;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySecretStore::default());
    let home =
        AccountHome::open_with_secret_store(dir.path(), store.clone(), IosOptions::default());
    let account = home.create_account("wipe-secret").unwrap();
    let account_dir = dir.path().join("accounts").join(&account.label);
    let secret_path = account_dir.join("secret.json");
    std::fs::write(&secret_path, b"local signing key").unwrap();
    std::fs::write(
        account_dir.join(".external-sqlcipher-secret"),
        b"database key",
    )
    .unwrap();
    std::fs::write(account_dir.join("session.sqlite"), b"encrypted state").unwrap();
    let mut signing_file = std::fs::File::open(&secret_path).unwrap();
    let mut database_file =
        std::fs::File::open(account_dir.join(".external-sqlcipher-secret")).unwrap();

    // Force tombstone deletion to fail after `remove_account` has renamed the
    // live account out of `accounts/`, letting the test inspect the tombstone.
    let stubborn_dir = account_dir.join("stubborn");
    std::fs::create_dir(&stubborn_dir).unwrap();
    let mut permissions = std::fs::metadata(&stubborn_dir).unwrap().permissions();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&stubborn_dir, permissions).unwrap();

    let remove = || {
        let denied = match std::fs::read_dir(&stubborn_dir) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => true,
            Err(error) => panic!("opening deletion failure fixture: {error}"),
        };
        #[cfg(target_os = "linux")]
        assert!(denied, "the test must exercise a real filesystem failure");
        home.remove_account(&account.label).unwrap();
        denied
    };
    #[cfg(target_os = "linux")]
    let denied = without_dac_override(remove);
    #[cfg(not(target_os = "linux"))]
    let denied = remove();

    let tombstone_root = dir.path().join(".wipe-tombstones");
    let tombstones: Vec<_> = std::fs::read_dir(&tombstone_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(tombstones.len(), usize::from(denied));
    assert!(!dir.path().join("accounts").join(&account.label).exists());
    for (file, len) in [
        (&mut signing_file, b"local signing key".len()),
        (&mut database_file, b"database key".len()),
    ] {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, vec![0; len]);
    }
    assert!(store.keys.lock().unwrap().is_empty());
    if !denied {
        // Other Unix superusers may have traversed the directory despite its mode.
        return;
    }
    assert!(tombstones[0].join("stubborn").is_dir());
    assert!(!tombstones[0].join("secret.json").exists());
    assert!(!tombstones[0].join(".external-sqlcipher-secret").exists());
    assert!(!tombstones[0].join("session.sqlite").exists());
    drop(home);

    // A later filesystem retry must not repeat completed vault deletion.
    store.fail_remove.store(true, Ordering::SeqCst);
    let stubborn_tombstone = tombstones[0].join("stubborn");
    let mut permissions = std::fs::metadata(&stubborn_tombstone)
        .unwrap()
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&stubborn_tombstone, permissions).unwrap();
    let recovered = AccountHome::open_with_secret_store(dir.path(), store, IosOptions::default());
    assert!(
        tombstones[0].exists(),
        "constructors must not replay cleanup"
    );
    recovered.resume_wipe_cleanup().unwrap();
    assert!(!tombstones[0].exists());
}

#[cfg(target_os = "linux")]
fn without_dac_override<T: Send>(operation: impl FnOnce() -> T + Send) -> T {
    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // Raw capability syscalls affect only this worker thread. The rest of the
    // test process, including tempfile cleanup, keeps its original credentials.
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                const VERSION_3: u32 = 0x2008_0522;
                const DAC_CAPS: u32 = (1 << 1) | (1 << 2); // DAC_OVERRIDE, DAC_READ_SEARCH
                let mut header = CapabilityHeader {
                    version: VERSION_3,
                    pid: 0,
                };
                let mut data = [CapabilityData::default(); 2];
                // These are the Linux v3 capability ABI structures. A zero pid
                // selects the calling thread, and both buffers live through the call.
                let get =
                    unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) };
                assert_eq!(get, 0, "capget: {}", std::io::Error::last_os_error());
                if data[0].effective & DAC_CAPS != 0 {
                    data[0].effective &= !DAC_CAPS;
                    let set = unsafe {
                        libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr())
                    };
                    assert_eq!(set, 0, "capset: {}", std::io::Error::last_os_error());
                }
                operation()
            })
            .join()
            .unwrap()
    })
}

#[cfg(target_os = "linux")]
#[test]
fn receipt_retry_requires_sync() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
    let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
    let account_id = keys.public_key().to_hex();
    let home = "11".repeat(32);
    let owner = "22".repeat(32);
    let credential = SecretCredential {
        label: "retry",
        account_id_hex: &account_id,
        home_id: &home,
        owner_id: &owner,
        kind: SecretCredentialKind::Signing,
    };
    store
        .acquire_secret(credential, SecretClaimMode::CreateOnly, Some(&keys))
        .unwrap();
    let receipt = file_receipts(dir.path()).pop().unwrap();
    let before = std::fs::read(&receipt).unwrap();
    let parent = receipt.parent().unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o100)).unwrap();
    let retry = without_dac_override(|| {
        let loaded = store.load_secret(credential).unwrap();
        assert_eq!(loaded.secret_key(), keys.secret_key());
        store.acquire_secret(credential, SecretClaimMode::CreateOnly, None)
    });
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(retry, Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    let retried = store
        .acquire_secret(credential, SecretClaimMode::CreateOnly, None)
        .unwrap();
    assert_eq!(retried.origin, SecretOrigin::Created);
    assert_eq!(retried.keys.secret_key(), keys.secret_key());
    assert_eq!(std::fs::read(receipt).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
fn wipe_waits_for_rename_sync() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let accounts = dir.path().join("accounts");
    let tombstone = dir.path().join(".wipe-tombstones/interrupted.0.0");
    let secret = tombstone.join("secret.json");
    fs_private::create_dir_all_private(&accounts).unwrap();
    fs_private::create_dir_all_private(&tombstone).unwrap();
    fs_private::write_private(&secret, b"tombstoned secret").unwrap();
    std::fs::set_permissions(&accounts, std::fs::Permissions::from_mode(0o100)).unwrap();

    without_dac_override(|| home.resume_wipe_cleanup()).unwrap();
    std::fs::set_permissions(&accounts, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(std::fs::read(&secret).unwrap(), b"tombstoned secret");

    home.resume_wipe_cleanup().unwrap();
    assert!(!secret.exists());
    assert!(!tombstone.exists());
}

#[test]
fn account_home_reveal_nsec_round_trips_to_stored_account_id() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let imported = home.import_nostr_account(nsec).unwrap();

    let revealed: Zeroizing<String> = home.reveal_nsec(&imported.account_id_hex).unwrap();
    assert_eq!(revealed.len(), 63);
    assert!(revealed.starts_with("nsec1"));
    // The revealed nsec parses back to the same public key as the account id.
    assert_eq!(
        nostr::prelude::Keys::parse(revealed.as_str())
            .unwrap()
            .public_key()
            .to_hex(),
        imported.account_id_hex
    );
}

#[test]
fn account_home_key_security_byte_defaults_secure_and_flips_after_reveal() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    let created = home.create_nostr_account().unwrap();

    // No reveal yet: NIP-49 status is unknown/untracked by default.
    assert_eq!(
        home.key_security_byte(&created.account_id_hex).unwrap(),
        0x02
    );

    home.reveal_nsec(&created.account_id_hex).unwrap();
    assert_eq!(
        home.key_security_byte(&created.account_id_hex).unwrap(),
        0x00
    );

    // The marker is persisted: a fresh home at the same root still reads 0x00.
    let reopened = AccountHome::open(dir.path());
    assert_eq!(
        reopened.key_security_byte(&created.account_id_hex).unwrap(),
        0x00
    );
}

#[test]
fn account_home_reveal_nsec_rejects_unknown_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    assert!(matches!(
        home.reveal_nsec("does-not-exist"),
        Err(AccountHomeError::UnknownAccount(_))
    ));
}

#[test]
fn account_home_reveal_nsec_rejects_public_only_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = "0000000000000000000000000000000000000000000000000000000000000001";

    home.add_public_account(public_key).unwrap();

    assert!(matches!(
        home.reveal_nsec(public_key),
        Err(AccountHomeError::SecretNotFound(_))
    ));
}

#[test]
fn account_home_exports_nip49_encrypted_secret_without_marking_key_insecure() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let imported = home.import_nostr_account(nsec).unwrap();

    let ncryptsec = home
        .export_encrypted_secret_key(&imported.account_id_hex, "test123")
        .unwrap();

    assert!(ncryptsec.starts_with("ncryptsec1"));
    let encrypted = EncryptedSecretKey::from_bech32(&ncryptsec).unwrap();
    assert_eq!(encrypted.log_n(), 18);
    assert_eq!(encrypted.key_security(), KeySecurity::Unknown);
    let decrypted = encrypted.decrypt("test123").unwrap();
    assert_eq!(
        decrypted.to_secret_hex(),
        home.load_signing_keys(&imported.account_id_hex)
            .unwrap()
            .secret_key()
            .to_secret_hex()
    );
    // Encrypted export does not reveal the raw key, so the NIP-49 security byte
    // remains "unknown/untracked" instead of being downgraded to weak.
    assert_eq!(
        home.key_security_byte(&imported.account_id_hex).unwrap(),
        0x02
    );
}

#[test]
fn account_home_nip49_export_uses_persisted_weak_security_after_raw_reveal() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let created = home.create_nostr_account().unwrap();

    home.reveal_nsec(&created.account_id_hex).unwrap();

    let ncryptsec = home
        .export_encrypted_secret_key(&created.account_id_hex, "test123")
        .unwrap();

    let encrypted = EncryptedSecretKey::from_bech32(&ncryptsec).unwrap();
    assert_eq!(encrypted.key_security(), KeySecurity::Weak);
    assert_eq!(
        home.key_security_byte(&created.account_id_hex).unwrap(),
        0x00
    );
}

#[test]
fn account_home_nip49_export_rejects_empty_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let created = home.create_nostr_account().unwrap();

    assert!(matches!(
        home.export_encrypted_secret_key(&created.account_id_hex, ""),
        Err(AccountHomeError::EmptyPassphrase)
    ));
}

#[test]
fn account_home_nip49_export_rejects_public_only_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let public_key = "0000000000000000000000000000000000000000000000000000000000000001";

    home.add_public_account(public_key).unwrap();

    assert!(matches!(
        home.export_encrypted_secret_key(public_key, "test123"),
        Err(AccountHomeError::SecretNotFound(_))
    ));
}

include!("support/receipt_fixture.rs");

#[test]
fn onboarding_latest_evidence_and_recovery_journal_are_private() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_nostr_account().unwrap();
    home.set_account_signed_out(&account.label, true).unwrap();
    let first = br#"{"approved":true,"signed":"uncertain"}"#;
    home.set_account_onboarding(&account.label, first).unwrap();
    home.archive_account_onboarding(&account.label).unwrap();
    assert_eq!(
        home.cancelled_account_onboarding(&account.label)
            .unwrap()
            .unwrap(),
        first
    );
    let latest = b"latest cancellation";
    home.set_account_onboarding(&account.label, latest).unwrap();
    home.archive_account_onboarding(&account.label).unwrap();
    home.archive_account_onboarding(&account.label).unwrap();
    assert_eq!(
        home.cancelled_account_onboarding(&account.label)
            .unwrap()
            .unwrap(),
        latest
    );
    let opaque = b"opaque recovery journal";
    assert!(
        home.finish_recovered_account_onboarding(&account.label, b"tombstone")
            .is_err()
    );
    home.set_account_onboarding_recovery(&account.label, opaque)
        .unwrap();
    home.finish_recovered_account_onboarding(&account.label, b"tombstone")
        .unwrap();
    assert_eq!(
        home.account_onboarding_recovery(&account.label)
            .unwrap()
            .unwrap(),
        opaque
    );
    assert_eq!(
        home.cancelled_account_onboarding(&account.label)
            .unwrap()
            .unwrap(),
        b"tombstone"
    );
    let directory = home.account_dir(&account.label);
    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["onboarding-cancelled.json", "onboarding-recovery.json"] {
            assert_eq!(
                std::fs::metadata(directory.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn replaceable_record_floors_only_advance_and_survive_reopen() {
    let root = tempfile::tempdir().unwrap();
    let home = AccountHome::open(root.path());
    let account = home.create_nostr_account().unwrap();
    assert!(
        home.replaceable_record_floors(&account.label)
            .unwrap()
            .is_empty()
    );

    home.advance_replaceable_record_floor(&account.label, 3, 20)
        .unwrap();
    home.advance_replaceable_record_floor(&account.label, 3, 10)
        .unwrap();
    home.advance_replaceable_record_floor(&account.label, 0, 5)
        .unwrap();

    let reopened = AccountHome::open(root.path());
    let floors = reopened
        .replaceable_record_floors(&account.account_id_hex)
        .unwrap();
    assert_eq!(floors.get(&3), Some(&20), "a floor never moves backwards");
    assert_eq!(floors.get(&0), Some(&5));
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(
            reopened
                .account_dir(&account.label)
                .join("replaceable-floors.json"),
        )
        .unwrap()
        .permissions()
        .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
