//! Host-supplied account-secret storage.
//!
//! By default account signing keys live in the platform keychain
//! ([`crate::Marmot::new`]). A host that already owns an encrypted store —
//! a desktop client with a password-sealed vault, an iOS host that wants
//! its own Keychain access-control flags, an Android host layering its own
//! Keystore policy — implements [`SecretStore`] and constructs through
//! [`crate::Marmot::new_with_secret_store`] instead.
//!
//! The boundary is strings only: the signing key crosses as secret-key hex
//! and an account is identified by its `label` plus `account_id_hex`, which
//! is everything a store needs from `AccountSummary`.

use std::sync::Arc;

use marmot_account::{AccountSecretStore, AccountSummary};
use zeroize::Zeroizing;

use crate::MarmotKitError;

/// Foreign-implemented storage for account signing keys.
///
/// Implementations must be thread-safe: the runtime calls these methods
/// from worker threads and may call them concurrently.
///
/// This is a storage boundary, not a security boundary. The plaintext
/// secret-key hex crosses it in both directions; whatever protection the
/// key gets (encryption, an OS keystore, a password-derived seal) is the
/// implementation's responsibility.
#[uniffi::export(with_foreign)]
pub trait SecretStore: Send + Sync {
    /// Whether a credential is stored under `label`.
    fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError>;

    /// Whether a credential is stored under `account_id_hex`. Stores that
    /// key one credential per label report `false`.
    fn has_secret_for_account_id(&self, account_id_hex: String) -> Result<bool, MarmotKitError>;

    /// Persist `secret_key_hex` for this account, replacing any existing
    /// credential.
    fn write_secret(
        &self,
        label: String,
        account_id_hex: String,
        secret_key_hex: String,
    ) -> Result<(), MarmotKitError>;

    /// Return the stored secret-key hex, or [`MarmotKitError::SecretNotFound`]
    /// when this account has no credential.
    fn load_secret(&self, label: String, account_id_hex: String) -> Result<String, MarmotKitError>;

    /// Remove this account's credential. Removing a missing credential
    /// succeeds.
    fn remove_secret(&self, label: String, account_id_hex: String) -> Result<(), MarmotKitError>;
}

/// Adapts a foreign [`SecretStore`] to the engine's [`AccountSecretStore`].
pub(crate) struct ForeignSecretStore {
    store: Arc<dyn SecretStore>,
}

impl ForeignSecretStore {
    pub(crate) fn new(store: Arc<dyn SecretStore>) -> Self {
        Self { store }
    }
}

impl AccountSecretStore for ForeignSecretStore {
    fn has_secret_for_label(&self, label: &str) -> marmot_account::AccountHomeResult<bool> {
        self.store
            .has_secret_for_label(label.to_owned())
            .map_err(account_home_error)
    }

    fn has_secret_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> marmot_account::AccountHomeResult<bool> {
        self.store
            .has_secret_for_account_id(account_id_hex.to_owned())
            .map_err(account_home_error)
    }

    fn write_secret(
        &self,
        account: &AccountSummary,
        keys: &nostr::Keys,
    ) -> marmot_account::AccountHomeResult<()> {
        let secret_key_hex = Zeroizing::new(keys.secret_key().to_secret_hex());
        self.store
            .write_secret(
                account.label.clone(),
                account.account_id_hex.clone(),
                secret_key_hex.to_string(),
            )
            .map_err(account_home_error)
    }

    fn load_secret(
        &self,
        account: &AccountSummary,
    ) -> marmot_account::AccountHomeResult<nostr::Keys> {
        let secret_key_hex = Zeroizing::new(
            self.store
                .load_secret(account.label.clone(), account.account_id_hex.clone())
                .map_err(account_home_error)?,
        );
        nostr::Keys::parse(secret_key_hex.as_str())
            .map_err(|_| marmot_account::AccountHomeError::InvalidSecretKey)
    }

    fn remove_secret(&self, account: &AccountSummary) -> marmot_account::AccountHomeResult<()> {
        self.store
            .remove_secret(account.label.clone(), account.account_id_hex.clone())
            .map_err(account_home_error)
    }
}

/// Map a host-reported failure onto the account layer's existing secret-store
/// error variants. `SecretNotFound` and an unavailable store are the two the
/// engine reacts to differently; everything else is opaque store failure.
fn account_home_error(error: MarmotKitError) -> marmot_account::AccountHomeError {
    use marmot_account::AccountHomeError;

    match error {
        MarmotKitError::SecretNotFound { details } => AccountHomeError::SecretNotFound(details),
        MarmotKitError::KeystoreUnavailable { details } => {
            AccountHomeError::SecretStoreUnavailable(details)
        }
        other => AccountHomeError::SecretStore(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct MapStore {
        entries: Mutex<Vec<(String, String)>>,
    }

    impl SecretStore for MapStore {
        fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .iter()
                .any(|(key, _)| *key == label))
        }

        fn has_secret_for_account_id(
            &self,
            _account_id_hex: String,
        ) -> Result<bool, MarmotKitError> {
            Ok(false)
        }

        fn write_secret(
            &self,
            label: String,
            _account_id_hex: String,
            secret_key_hex: String,
        ) -> Result<(), MarmotKitError> {
            self.entries.lock().unwrap().push((label, secret_key_hex));
            Ok(())
        }

        fn load_secret(
            &self,
            label: String,
            _account_id_hex: String,
        ) -> Result<String, MarmotKitError> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .find(|(key, _)| *key == label)
                .map(|(_, secret)| secret.clone())
                .ok_or(MarmotKitError::SecretNotFound { details: label })
        }

        fn remove_secret(
            &self,
            label: String,
            _account_id_hex: String,
        ) -> Result<(), MarmotKitError> {
            self.entries
                .lock()
                .unwrap()
                .retain(|(key, _)| *key != label);
            Ok(())
        }
    }

    fn summary(keys: &nostr::Keys) -> AccountSummary {
        AccountSummary {
            label: "vault-account".to_owned(),
            account_id_hex: keys.public_key().to_hex(),
            local_signing: true,
            external_signing: false,
            signed_out: false,
        }
    }

    #[test]
    fn foreign_store_roundtrips_the_signing_key() {
        let store = ForeignSecretStore::new(Arc::new(MapStore {
            entries: Mutex::new(Vec::new()),
        }));
        let keys = nostr::Keys::generate();
        let account = summary(&keys);

        assert!(!store.has_secret_for_label(&account.label).unwrap());
        store.write_secret(&account, &keys).unwrap();
        assert!(store.has_secret_for_label(&account.label).unwrap());
        assert_eq!(
            store.load_secret(&account).unwrap().secret_key(),
            keys.secret_key()
        );

        store.remove_secret(&account).unwrap();
        assert!(!store.has_secret_for_label(&account.label).unwrap());
        assert!(matches!(
            store.load_secret(&account),
            Err(marmot_account::AccountHomeError::SecretNotFound(_))
        ));
    }

    #[test]
    fn host_errors_map_onto_existing_secret_store_variants() {
        assert!(matches!(
            account_home_error(MarmotKitError::SecretNotFound {
                details: "gone".into()
            }),
            marmot_account::AccountHomeError::SecretNotFound(_)
        ));
        assert!(matches!(
            account_home_error(MarmotKitError::KeystoreUnavailable {
                details: "locked".into()
            }),
            marmot_account::AccountHomeError::SecretStoreUnavailable(_)
        ));
        assert!(matches!(
            account_home_error(MarmotKitError::Runtime {
                details: "boom".into()
            }),
            marmot_account::AccountHomeError::SecretStore(_)
        ));
    }
}
