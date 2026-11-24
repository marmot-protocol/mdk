//! Host-supplied storage for owned account credentials.

use crate::MarmotKitError;
use marmot_account::AccountSecretStore;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SecretCredentialKind {
    Signing,
    ExternalDatabase,
    Nip46Session,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct SecretCredential {
    pub label: String,
    pub account_id_hex: String,
    pub home_id: String,
    pub owner_id: String,
    pub kind: SecretCredentialKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SecretClaimMode {
    CreateOnly,
    AdoptOnly,
    CreateOrAdopt,
    MigrateLegacy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SecretOrigin {
    Created,
    Existing,
}

#[derive(Clone, uniffi::Record)]
pub struct AcquiredSecret {
    pub secret_key_hex: String,
    pub origin: SecretOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SecretReleaseMode {
    DeleteIfUnowned,
    Preserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SecretReleaseOutcome {
    Released,
    /// Managed retirement and deletion completed; only raw legacy cleanup remains unresolved.
    PendingLegacy,
}

impl From<marmot_account::SecretCredential<'_>> for SecretCredential {
    fn from(record: marmot_account::SecretCredential<'_>) -> Self {
        Self {
            label: record.label.to_owned(),
            account_id_hex: record.account_id_hex.to_owned(),
            home_id: record.home_id.to_owned(),
            owner_id: record.owner_id.to_owned(),
            kind: match record.kind {
                marmot_account::SecretCredentialKind::Signing => SecretCredentialKind::Signing,
                marmot_account::SecretCredentialKind::ExternalDatabase => {
                    SecretCredentialKind::ExternalDatabase
                }
                marmot_account::SecretCredentialKind::Nip46Session => {
                    SecretCredentialKind::Nip46Session
                }
            },
        }
    }
}

/// Host storage for immutable per-owner credential copies.
///
/// Calls may run synchronously on a constructor's calling thread or concurrently
/// on runtime threads. Implementations must be thread-safe and must not wait for
/// the UI thread. The runtime retains the callback object while it uses it.
/// Do not re-enter account-home mutations on the same root, including through
/// another independently opened client.
///
/// Plaintext secret-key hex crosses this boundary in both directions. Hosts
/// provide encryption and credential protection, and clear temporary secret copies.
pub trait SecretStore: Send + Sync {
    /// Stable, nonsecret identity of the physical vault and credential namespace,
    /// including service or tenant. Keep it stable across restarts and lock/unlock.
    /// Different vaults require different identities. Keep the target fixed for
    /// this object's lifetime; switching vaults requires a new callback object.
    fn cleanup_namespace(&self) -> Result<String, MarmotKitError>;

    /// Whether discoverable signing material is stored under this label.
    fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError>;

    /// Whether discoverable signing material exists for this account ID.
    fn has_secret_for_account_id(&self, account_id_hex: String) -> Result<bool, MarmotKitError>;

    /// Acquire an immutable copy before returning. Same-owner retries preserve
    /// the original material and origin; retired owner IDs must never be reused.
    /// Signing discovery is shared across homes, auxiliary discovery home-scoped.
    /// CreateOnly requires a proposal and rejects existing material. AdoptOnly
    /// requires existing material. CreateOrAdopt creates only with a proposal.
    /// Any proposal must match adopted material. Signing keys must derive the
    /// requested account ID; auxiliary IDs are storage identifiers.
    /// Only MigrateLegacy may inspect independent legacy material. Retain a
    /// legacy pointer for pending cleanup; ordinary claims use managed sources.
    /// Return SecretNotFound only if there is no usable source and no committed
    /// or pending receipt for this owner. If a lookup or write is uncertain,
    /// return a different failure so the runtime keeps the owner for recovery.
    fn acquire_secret(
        &self,
        record: SecretCredential,
        mode: SecretClaimMode,
        proposed_hex: Option<String>,
    ) -> Result<AcquiredSecret, MarmotKitError>;

    /// Return this owner's secret hex, or SecretNotFound when no active copy exists.
    fn load_secret(&self, record: SecretCredential) -> Result<String, MarmotKitError>;

    /// Retire before deleting this owner's copy; never delete another owner's key.
    /// Preserve retains discoverable material until a new owner owns a copy.
    /// Old release retries cannot resurrect consumed holds. Retain ambiguous
    /// independent legacy material and return PendingLegacy instead of claiming
    /// physical erasure. Retirement metadata must outlive the account record.
    /// PendingLegacy confirms managed retirement and deletion completed. An
    /// uncertain or failed managed deletion returns an error, not PendingLegacy.
    fn release_secret(
        &self,
        record: SecretCredential,
        mode: SecretReleaseMode,
    ) -> Result<SecretReleaseOutcome, MarmotKitError>;

    /// Replay retired-owner cleanup even when no account wipe remains pending.
    /// Retain retirement metadata; never infer exclusive ownership of legacy keys.
    fn reconcile_cleanup(&self) -> Result<(), MarmotKitError>;
}

pub(crate) struct ForeignSecretStore {
    store: Arc<dyn SecretStore>,
}

impl ForeignSecretStore {
    pub(crate) fn new(store: Arc<dyn SecretStore>) -> Self {
        Self { store }
    }
}

impl AccountSecretStore for ForeignSecretStore {
    fn cleanup_namespace(&self) -> marmot_account::AccountHomeResult<String> {
        self.store
            .cleanup_namespace()
            .map(|namespace| format!("foreign:{namespace}"))
            .map_err(account_home_error)
    }

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

    fn acquire_secret(
        &self,
        record: marmot_account::SecretCredential<'_>,
        mode: marmot_account::SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> marmot_account::AccountHomeResult<marmot_account::AcquiredSecret> {
        let proposed_hex = proposed.map(|keys| Zeroizing::new(keys.secret_key().to_secret_hex()));
        let acquired = self
            .store
            .acquire_secret(
                record.into(),
                match mode {
                    marmot_account::SecretClaimMode::CreateOnly => SecretClaimMode::CreateOnly,
                    marmot_account::SecretClaimMode::AdoptOnly => SecretClaimMode::AdoptOnly,
                    marmot_account::SecretClaimMode::CreateOrAdopt => {
                        SecretClaimMode::CreateOrAdopt
                    }
                    marmot_account::SecretClaimMode::MigrateLegacy => {
                        SecretClaimMode::MigrateLegacy
                    }
                },
                proposed_hex.as_ref().map(|hex| hex.to_string()),
            )
            .map_err(account_home_error)?;
        let secret = Zeroizing::new(acquired.secret_key_hex);
        let keys = parse_secret(&secret, record)?;
        if proposed.is_some_and(|proposed| proposed.secret_key() != keys.secret_key()) {
            return Err(marmot_account::AccountHomeError::InvalidSecretKey);
        }
        Ok(marmot_account::AcquiredSecret {
            keys,
            origin: match acquired.origin {
                SecretOrigin::Created => marmot_account::SecretOrigin::Created,
                SecretOrigin::Existing => marmot_account::SecretOrigin::Existing,
            },
        })
    }

    fn load_secret(
        &self,
        record: marmot_account::SecretCredential<'_>,
    ) -> marmot_account::AccountHomeResult<nostr::prelude::Keys> {
        let secret = Zeroizing::new(
            self.store
                .load_secret(record.into())
                .map_err(account_home_error)?,
        );
        parse_secret(&secret, record)
    }

    fn release_secret(
        &self,
        record: marmot_account::SecretCredential<'_>,
        mode: marmot_account::SecretReleaseMode,
    ) -> marmot_account::AccountHomeResult<marmot_account::SecretReleaseOutcome> {
        self.store
            .release_secret(
                record.into(),
                match mode {
                    marmot_account::SecretReleaseMode::DeleteIfUnowned => {
                        SecretReleaseMode::DeleteIfUnowned
                    }
                    marmot_account::SecretReleaseMode::Preserve => SecretReleaseMode::Preserve,
                },
            )
            .map(|outcome| match outcome {
                SecretReleaseOutcome::Released => marmot_account::SecretReleaseOutcome::Released,
                SecretReleaseOutcome::PendingLegacy => {
                    marmot_account::SecretReleaseOutcome::PendingLegacy
                }
            })
            .map_err(account_home_error)
    }

    fn reconcile_cleanup(&self) -> marmot_account::AccountHomeResult<()> {
        self.store.reconcile_cleanup().map_err(account_home_error)
    }
}

fn parse_secret(
    secret: &str,
    record: marmot_account::SecretCredential<'_>,
) -> marmot_account::AccountHomeResult<nostr::prelude::Keys> {
    if secret.len() != 64 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(marmot_account::AccountHomeError::InvalidSecretKey);
    }
    let keys = nostr::prelude::Keys::parse(secret)
        .map_err(|_| marmot_account::AccountHomeError::InvalidSecretKey)?;
    if record.kind == marmot_account::SecretCredentialKind::Signing
        && keys.public_key().to_hex() != record.account_id_hex
    {
        return Err(marmot_account::AccountHomeError::InvalidSecretKey);
    }
    Ok(keys)
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
    use super::*;
    use nostr::prelude::ToBech32;
    use std::sync::Mutex;

    // Protocol probe for the adapter, not a vault supplied to an account home.
    struct CallbackProbe {
        record: SecretCredential,
        claim: SecretClaimMode,
        proposal: Option<String>,
        secret: Mutex<String>,
        origin: SecretOrigin,
        release: SecretReleaseMode,
        outcome: SecretReleaseOutcome,
    }

    impl SecretStore for CallbackProbe {
        fn cleanup_namespace(&self) -> Result<String, MarmotKitError> {
            Ok("local-file:host-vault".into())
        }

        fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError> {
            Ok(self.record.kind == SecretCredentialKind::Signing && self.record.label == label)
        }

        fn has_secret_for_account_id(
            &self,
            account_id_hex: String,
        ) -> Result<bool, MarmotKitError> {
            Ok(self.record.kind == SecretCredentialKind::Signing
                && self.record.account_id_hex == account_id_hex)
        }

        fn acquire_secret(
            &self,
            record: SecretCredential,
            mode: SecretClaimMode,
            proposed_hex: Option<String>,
        ) -> Result<AcquiredSecret, MarmotKitError> {
            let proposed = proposed_hex.map(Zeroizing::new);
            assert_eq!(record, self.record);
            assert_eq!(mode, self.claim);
            assert!(proposed.as_ref().map(|value| value.as_str()) == self.proposal.as_deref());
            Ok(AcquiredSecret {
                secret_key_hex: self.secret.lock().unwrap().clone(),
                origin: self.origin,
            })
        }

        fn load_secret(&self, record: SecretCredential) -> Result<String, MarmotKitError> {
            assert_eq!(record, self.record);
            Ok(self.secret.lock().unwrap().clone())
        }

        fn release_secret(
            &self,
            record: SecretCredential,
            mode: SecretReleaseMode,
        ) -> Result<SecretReleaseOutcome, MarmotKitError> {
            assert_eq!(record, self.record);
            assert_eq!(mode, self.release);
            Ok(self.outcome)
        }

        fn reconcile_cleanup(&self) -> Result<(), MarmotKitError> {
            Err(MarmotKitError::KeystoreUnavailable {
                details: "cleanup locked".into(),
            })
        }
    }

    #[test]
    fn foreign_owned_roundtrip() {
        use marmot_account::{
            SecretClaimMode as Claim, SecretCredentialKind as Kind, SecretOrigin as Origin,
            SecretReleaseMode as Release, SecretReleaseOutcome as Outcome,
        };
        let keys = nostr::prelude::Keys::generate();
        let account_id = keys.public_key().to_hex();
        let home_id = "11".repeat(32);
        let owner_id = "22".repeat(32);
        for (
            kind,
            foreign_kind,
            claim,
            foreign_claim,
            origin,
            foreign_origin,
            release,
            foreign_release,
            outcome,
            foreign_outcome,
        ) in [
            (
                Kind::Signing,
                SecretCredentialKind::Signing,
                Claim::CreateOnly,
                SecretClaimMode::CreateOnly,
                Origin::Created,
                SecretOrigin::Created,
                Release::DeleteIfUnowned,
                SecretReleaseMode::DeleteIfUnowned,
                Outcome::Released,
                SecretReleaseOutcome::Released,
            ),
            (
                Kind::ExternalDatabase,
                SecretCredentialKind::ExternalDatabase,
                Claim::AdoptOnly,
                SecretClaimMode::AdoptOnly,
                Origin::Existing,
                SecretOrigin::Existing,
                Release::Preserve,
                SecretReleaseMode::Preserve,
                Outcome::PendingLegacy,
                SecretReleaseOutcome::PendingLegacy,
            ),
            (
                Kind::Nip46Session,
                SecretCredentialKind::Nip46Session,
                Claim::CreateOrAdopt,
                SecretClaimMode::CreateOrAdopt,
                Origin::Existing,
                SecretOrigin::Existing,
                Release::DeleteIfUnowned,
                SecretReleaseMode::DeleteIfUnowned,
                Outcome::Released,
                SecretReleaseOutcome::Released,
            ),
            (
                Kind::Signing,
                SecretCredentialKind::Signing,
                Claim::MigrateLegacy,
                SecretClaimMode::MigrateLegacy,
                Origin::Existing,
                SecretOrigin::Existing,
                Release::Preserve,
                SecretReleaseMode::Preserve,
                Outcome::PendingLegacy,
                SecretReleaseOutcome::PendingLegacy,
            ),
        ] {
            let record = marmot_account::SecretCredential {
                label: "vault-account",
                account_id_hex: &account_id,
                home_id: &home_id,
                owner_id: &owner_id,
                kind,
            };
            let proposal = if claim == Claim::CreateOnly {
                Some(&keys)
            } else {
                None
            };
            let host = Arc::new(CallbackProbe {
                record: SecretCredential {
                    label: "vault-account".into(),
                    account_id_hex: account_id.clone(),
                    home_id: home_id.clone(),
                    owner_id: owner_id.clone(),
                    kind: foreign_kind,
                },
                claim: foreign_claim,
                proposal: proposal.map(|keys| keys.secret_key().to_secret_hex()),
                secret: Mutex::new(keys.secret_key().to_secret_hex()),
                origin: foreign_origin,
                release: foreign_release,
                outcome: foreign_outcome,
            });
            let store = ForeignSecretStore::new(host.clone());
            assert_eq!(
                store.cleanup_namespace().unwrap(),
                "foreign:local-file:host-vault"
            );
            assert_eq!(
                store.has_secret_for_label(record.label).unwrap(),
                kind == Kind::Signing
            );
            assert_eq!(
                store.has_secret_for_account_id(&account_id).unwrap(),
                kind == Kind::Signing
            );
            let acquired = store.acquire_secret(record, claim, proposal).unwrap();
            assert_eq!(acquired.keys.secret_key(), keys.secret_key());
            assert_eq!(acquired.origin, origin);
            assert_eq!(
                store.load_secret(record).unwrap().secret_key(),
                keys.secret_key()
            );
            assert_eq!(store.release_secret(record, release).unwrap(), outcome);
            assert!(matches!(store.reconcile_cleanup(),
                Err(marmot_account::AccountHomeError::SecretStoreUnavailable(details)) if details == "cleanup locked"));
            *host.secret.lock().unwrap() = "not-a-secret-key".into();
            assert!(matches!(
                store.load_secret(record),
                Err(marmot_account::AccountHomeError::InvalidSecretKey)
            ));
            assert!(matches!(
                store.acquire_secret(record, claim, proposal),
                Err(marmot_account::AccountHomeError::InvalidSecretKey)
            ));
        }
    }

    #[test]
    fn foreign_key_validation() {
        let keys = nostr::prelude::Keys::generate();
        let other = nostr::prelude::Keys::generate();
        let account_id = keys.public_key().to_hex();
        let mut record = marmot_account::SecretCredential {
            label: "vault-account",
            account_id_hex: &account_id,
            home_id: "home",
            owner_id: "owner",
            kind: marmot_account::SecretCredentialKind::Signing,
        };
        let host = Arc::new(CallbackProbe {
            record: record.into(),
            claim: SecretClaimMode::CreateOnly,
            proposal: Some(keys.secret_key().to_secret_hex()),
            secret: Mutex::new(other.secret_key().to_secret_hex()),
            origin: SecretOrigin::Created,
            release: SecretReleaseMode::DeleteIfUnowned,
            outcome: SecretReleaseOutcome::Released,
        });
        let store = ForeignSecretStore::new(host);
        assert!(matches!(
            store.load_secret(record),
            Err(marmot_account::AccountHomeError::InvalidSecretKey)
        ));
        assert!(matches!(
            store.acquire_secret(
                record,
                marmot_account::SecretClaimMode::CreateOnly,
                Some(&keys)
            ),
            Err(marmot_account::AccountHomeError::InvalidSecretKey)
        ));
        record.kind = marmot_account::SecretCredentialKind::ExternalDatabase;
        record.account_id_hex = "synthetic-storage-id";
        assert_eq!(
            parse_secret(&other.secret_key().to_secret_hex(), record)
                .unwrap()
                .secret_key(),
            other.secret_key()
        );
        let host = Arc::new(CallbackProbe {
            record: record.into(),
            claim: SecretClaimMode::CreateOnly,
            proposal: Some(keys.secret_key().to_secret_hex()),
            secret: Mutex::new(other.secret_key().to_secret_hex()),
            origin: SecretOrigin::Created,
            release: SecretReleaseMode::DeleteIfUnowned,
            outcome: SecretReleaseOutcome::Released,
        });
        let store = ForeignSecretStore::new(host);
        assert!(matches!(
            store.acquire_secret(
                record,
                marmot_account::SecretClaimMode::CreateOnly,
                Some(&keys)
            ),
            Err(marmot_account::AccountHomeError::InvalidSecretKey)
        ));
        for secret in [
            "not-hex".to_owned(),
            "0".repeat(64),
            keys.secret_key().to_bech32().unwrap(),
        ] {
            assert!(matches!(
                parse_secret(&secret, record),
                Err(marmot_account::AccountHomeError::InvalidSecretKey)
            ));
        }
    }

    #[test]
    fn host_error_mapping() {
        assert!(
            matches!(account_home_error(MarmotKitError::SecretNotFound { details: "gone".into() }),
            marmot_account::AccountHomeError::SecretNotFound(details) if details == "gone")
        );
        assert!(
            matches!(account_home_error(MarmotKitError::KeystoreUnavailable { details: "locked".into() }),
            marmot_account::AccountHomeError::SecretStoreUnavailable(details) if details == "locked")
        );
        assert!(
            matches!(account_home_error(MarmotKitError::Runtime { details: "boom".into() }),
            marmot_account::AccountHomeError::SecretStore(details) if details.contains("boom"))
        );
    }
}
