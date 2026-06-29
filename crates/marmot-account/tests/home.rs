use std::collections::HashMap;
use std::sync::{Mutex, Once};

use marmot_account::{
    AccountHome, AccountHomeError, AccountHomeResult, AccountSecretStore, AccountSummary,
};
use nostr::nips::nip19::FromBech32;
use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};

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
fn account_home_marks_local_file_secret_storage_and_locks_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());

    let created = home.create_nostr_account().unwrap();

    let secret_path = dir
        .path()
        .join("accounts")
        .join(&created.account_id_hex)
        .join("secret.json");
    let secret_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&secret_path).unwrap()).unwrap();
    assert_eq!(secret_json["version"], 1);
    assert_eq!(secret_json["backend"], "local-dev-file");
    assert!(secret_json["secret_key_hex"].as_str().is_some());

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
        home.account(&corrupted.label),
        Err(AccountHomeError::Json(_))
    ));
}

#[test]
fn account_home_rejects_path_like_labels() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    assert!(matches!(
        home.add_public_account("../alice"),
        Err(AccountHomeError::InvalidPublicKey)
    ));
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
    let secret_hex = nostr::Keys::generate().secret_key().to_secret_hex();

    assert!(matches!(
        home.import_account("C:evil", &secret_hex),
        Err(AccountHomeError::InvalidAccountLabel(label)) if label == "C:evil"
    ));
    assert!(!dir.path().join("accounts").join("C:evil").exists());
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
    assert!(matches!(
        home.load_signing_keys(public_key),
        Err(AccountHomeError::SecretNotFound(_))
    ));
}

#[test]
fn account_home_can_use_an_injected_secret_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(MemorySecretStore::default());
    let home = AccountHome::open_with_secret_store(dir.path(), store.clone());

    let created = home.create_nostr_account().unwrap();

    assert!(
        !dir.path()
            .join("accounts")
            .join(&created.account_id_hex)
            .join("secret.json")
            .exists()
    );
    let reopened = AccountHome::open_with_secret_store(dir.path(), store);
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
    let home = AccountHome::open_with_keychain(dir.path(), "com.marmot.test.dup-guard").unwrap();
    let secret_hex = nostr::Keys::generate().secret_key().to_secret_hex();

    home.import_account("label-one", &secret_hex).unwrap();

    assert!(matches!(
        home.import_account("label-two", &secret_hex),
        Err(AccountHomeError::AccountIdInUse(_))
    ));
}

#[test]
fn account_home_keychain_keeps_signing_secret_when_public_twin_record_is_removed() {
    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open_with_keychain(dir.path(), "com.marmot.test.public-twin").unwrap();
    let keys = nostr::Keys::generate();
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
    let home =
        AccountHome::open_with_keychain(dir.path(), "com.marmot.test.public-twin-reverse").unwrap();
    let keys = nostr::Keys::generate();
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
    let home = AccountHome::open_with_keychain(dir.path(), "com.marmot.test.legacy-twin").unwrap();
    let keys = nostr::Keys::generate();
    let account_id = keys.public_key().to_hex();

    home.import_account("label-one", &keys.secret_key().to_secret_hex())
        .unwrap();

    // Homes written before the account-id-aware duplicate guard could hold two
    // signing records sharing one keychain credential. Recreate that state.
    let twin = AccountSummary {
        label: "label-two".to_owned(),
        account_id_hex: account_id.clone(),
        local_signing: true,
        signed_out: false,
    };
    let twin_dir = dir.path().join("accounts").join(&twin.label);
    std::fs::create_dir_all(&twin_dir).unwrap();
    std::fs::write(
        twin_dir.join("account.json"),
        serde_json::to_vec(&twin).unwrap(),
    )
    .unwrap();

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
    let keys = nostr::Keys::generate();
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
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("wipe-secret").unwrap();
    let account_dir = dir.path().join("accounts").join(&account.label);
    let secret_path = account_dir.join("secret.json");
    assert!(secret_path.exists());

    // Force tombstone deletion to fail after `remove_account` has renamed the
    // live account out of `accounts/`, letting the test inspect the tombstone.
    let stubborn_dir = account_dir.join("stubborn");
    std::fs::create_dir(&stubborn_dir).unwrap();
    let mut permissions = std::fs::metadata(&stubborn_dir).unwrap().permissions();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&stubborn_dir, permissions).unwrap();

    home.remove_account(&account.label).unwrap();

    let tombstone_root = dir.path().join(".wipe-tombstones");
    let tombstones: Vec<_> = std::fs::read_dir(&tombstone_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(tombstones.len(), 1);
    assert!(!dir.path().join("accounts").join(&account.label).exists());
    assert!(!tombstones[0].join("secret.json").exists());

    // Restore permissions so the tempdir cleanup can remove the tombstone.
    let stubborn_tombstone = tombstones[0].join("stubborn");
    let mut permissions = std::fs::metadata(&stubborn_tombstone)
        .unwrap()
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&stubborn_tombstone, permissions).unwrap();
    std::fs::remove_dir_all(&tombstone_root).unwrap();
}

#[test]
fn account_home_reveal_nsec_round_trips_to_stored_account_id() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let imported = home.import_nostr_account(nsec).unwrap();

    let revealed = home.reveal_nsec(&imported.account_id_hex).unwrap();
    assert_eq!(revealed.len(), 63);
    assert!(revealed.starts_with("nsec1"));
    // The revealed nsec parses back to the same public key as the account id.
    assert_eq!(
        nostr::Keys::parse(&revealed).unwrap().public_key().to_hex(),
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

#[derive(Default)]
struct MemorySecretStore {
    keys: Mutex<HashMap<String, String>>,
}

impl AccountSecretStore for MemorySecretStore {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        Ok(self.keys.lock().unwrap().contains_key(label))
    }

    fn write_secret(
        &self,
        account: &marmot_account::AccountSummary,
        keys: &nostr::Keys,
    ) -> AccountHomeResult<()> {
        self.keys
            .lock()
            .unwrap()
            .insert(account.label.clone(), keys.secret_key().to_secret_hex());
        Ok(())
    }

    fn load_secret(
        &self,
        account: &marmot_account::AccountSummary,
    ) -> AccountHomeResult<nostr::Keys> {
        let secret = self
            .keys
            .lock()
            .unwrap()
            .get(&account.label)
            .unwrap()
            .clone();
        Ok(nostr::Keys::parse(&secret).unwrap())
    }

    fn remove_secret(&self, account: &marmot_account::AccountSummary) -> AccountHomeResult<()> {
        self.keys.lock().unwrap().remove(&account.label);
        Ok(())
    }
}
