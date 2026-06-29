//! Account secret storage: the `AccountSecretStore` trait and its file- and
//! keychain-backed implementations.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::home::{ACCOUNT_SECRET_FILE, AccountSummary, LOCAL_FILE_SECRET_BACKEND};
use crate::io::{read_secret_json, write_secret_json};
use crate::keyring::{initialize_keyring_store, map_keyring_error};

#[derive(Serialize, Deserialize)]
struct StoredAccountSecret {
    #[serde(default = "stored_secret_version")]
    version: u32,
    #[serde(default = "stored_secret_backend")]
    backend: String,
    secret_key_hex: String,
}

impl Drop for StoredAccountSecret {
    fn drop(&mut self) {
        // The local-file backend deserializes the raw signing key into this
        // struct, so wipe the plaintext hex when the record is dropped rather
        // than leaving it in a freed allocation.
        self.secret_key_hex.zeroize();
    }
}

pub trait AccountSecretStore: Send + Sync {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool>;
    /// Whether the store already holds a credential keyed by account id.
    /// Stores that key one credential per label never share entries across
    /// records, so the default reports `false`.
    fn has_secret_for_account_id(&self, _account_id_hex: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }
    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()>;
    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys>;
    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()>;
}

#[derive(Clone, Debug)]
pub struct LocalFileSecretStore {
    root: PathBuf,
}

impl LocalFileSecretStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn secret_path(&self, label: &str) -> PathBuf {
        self.root
            .join("accounts")
            .join(label)
            .join(ACCOUNT_SECRET_FILE)
    }
}

impl AccountSecretStore for LocalFileSecretStore {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        Ok(self.secret_path(label).exists())
    }

    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()> {
        // Keep the plaintext hex in a zeroizing buffer; the `StoredAccountSecret`
        // it is moved into wipes itself on drop, so the cleartext key never
        // outlives this call in a freed allocation.
        let secret_key_hex = Zeroizing::new(keys.secret_key().to_secret_hex());
        write_secret_json(
            self.secret_path(&account.label),
            &StoredAccountSecret {
                version: stored_secret_version(),
                backend: stored_secret_backend(),
                secret_key_hex: secret_key_hex.to_string(),
            },
        )
    }

    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
        let secret: StoredAccountSecret = read_secret_json(self.secret_path(&account.label))?;
        if secret.backend != LOCAL_FILE_SECRET_BACKEND {
            return Err(AccountHomeError::UnsupportedSecretBackend(
                secret.backend.clone(),
            ));
        }
        nostr::Keys::parse(&secret.secret_key_hex).map_err(|_| AccountHomeError::InvalidSecretKey)
    }

    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        scrub_and_remove_local_secret_file(&self.secret_path(&account.label))
    }
}

/// Best-effort overwrite of the local secret file's bytes before unlinking it.
///
/// The plaintext signing key sits at rest in this file, so deleting it with a
/// bare `fs::remove_file` would leave the key hex recoverable in freed disk
/// blocks. We first overwrite the file contents with zeros and `fsync`, then
/// unlink. A missing file is treated as already-removed (`NotFound -> Ok`) to
/// preserve idempotent removal semantics.
///
/// The scrub is best-effort: on some filesystems (copy-on-write, log-structured,
/// SSD wear-leveling) an in-place overwrite does not necessarily reach the
/// original physical blocks. This narrows the residue window for the dev-only
/// local-file backend without claiming a guaranteed secure erase.
pub(crate) fn scrub_and_remove_local_secret_file(path: &Path) -> AccountHomeResult<()> {
    match overwrite_file_with_zeros(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // The overwrite is best-effort: if it fails for any other reason we
        // still fall through to the unlink so removal is not blocked, but the
        // unlink error (if any) is the one we surface.
        Err(_) => {}
    }

    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn overwrite_file_with_zeros(path: &Path) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    if len > 0 {
        let zeros = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&zeros)?;
        file.sync_all()?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct KeychainSecretStore {
    service_name: String,
}

impl KeychainSecretStore {
    pub fn new(service_name: impl Into<String>) -> AccountHomeResult<Self> {
        let service_name = service_name.into().trim().to_owned();
        if service_name.is_empty() {
            return Err(AccountHomeError::EmptySecretStoreService);
        }
        initialize_keyring_store()?;
        Ok(Self { service_name })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    fn entry_for_account(&self, account_id_hex: &str) -> AccountHomeResult<keyring_core::Entry> {
        keyring_core::Entry::new(&self.service_name, account_id_hex).map_err(map_keyring_error)
    }
}

impl AccountSecretStore for KeychainSecretStore {
    fn has_secret_for_label(&self, _label: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }

    fn has_secret_for_account_id(&self, account_id_hex: &str) -> AccountHomeResult<bool> {
        match self.entry_for_account(account_id_hex)?.get_password() {
            Ok(_) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()> {
        self.entry_for_account(&account.account_id_hex)?
            .set_password(&keys.secret_key().to_secret_hex())
            .map_err(map_keyring_error)
    }

    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
        match self
            .entry_for_account(&account.account_id_hex)?
            .get_password()
        {
            Ok(secret_key) => {
                nostr::Keys::parse(&secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)
            }
            Err(keyring_core::Error::NoEntry) => Err(AccountHomeError::SecretNotFound(
                account.account_id_hex.clone(),
            )),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        match self
            .entry_for_account(&account.account_id_hex)?
            .delete_credential()
        {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_keyring_error(err)),
        }
    }
}

pub(crate) fn stored_secret_version() -> u32 {
    1
}

pub(crate) fn stored_secret_backend() -> String {
    LOCAL_FILE_SECRET_BACKEND.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_file_with_zeros_replaces_all_bytes_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        let secret = "deadbeef".repeat(8);
        fs::write(&path, secret.as_bytes()).unwrap();
        let original_len = fs::metadata(&path).unwrap().len();
        assert!(original_len > 0);

        overwrite_file_with_zeros(&path).unwrap();

        // The file still exists with the same length, but every byte that held
        // the plaintext key has been overwritten with zero before any unlink.
        let scrubbed = fs::read(&path).unwrap();
        assert_eq!(scrubbed.len() as u64, original_len);
        assert!(scrubbed.iter().all(|byte| *byte == 0));
        assert!(!scrubbed.windows(4).any(|w| w == b"dead"));
    }

    #[test]
    fn scrub_and_remove_local_secret_file_scrubs_then_unlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        fs::write(&path, b"00112233445566778899aabbccddeeff").unwrap();
        assert!(path.exists());

        scrub_and_remove_local_secret_file(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn scrub_and_remove_local_secret_file_is_ok_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(!path.exists());

        scrub_and_remove_local_secret_file(&path).unwrap();
    }

    #[test]
    fn local_file_remove_secret_scrubs_and_unlinks_the_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path());
        let keys = nostr::Keys::generate();
        let secret_hex = keys.secret_key().to_secret_hex();
        let account = AccountSummary {
            label: "scrub-me".to_owned(),
            account_id_hex: keys.public_key().to_hex(),
            local_signing: true,
            signed_out: false,
        };

        store.write_secret(&account, &keys).unwrap();
        let secret_path = store.secret_path(&account.label);
        let on_disk = fs::read_to_string(&secret_path).unwrap();
        assert!(on_disk.contains(&secret_hex));

        store.remove_secret(&account).unwrap();
        assert!(!secret_path.exists());

        // Removing an already-removed secret stays idempotent.
        store.remove_secret(&account).unwrap();
    }
}
