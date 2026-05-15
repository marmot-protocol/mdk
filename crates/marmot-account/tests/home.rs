use std::collections::HashMap;
use std::sync::Mutex;

use marmot_account::{AccountHome, AccountHomeError, AccountHomeResult, AccountSecretStore};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
