//! Account identity, files and secrets for Marmot.
//!
//! This crate is intentionally small. It owns the local account home: account
//! records, setup journals, signing-key storage and NIP-49 export. The
//! account-device runtime that drives a session over a transport lives in
//! `marmot-session`.

mod error;
#[path = "home/account.rs"]
mod home;
mod io;
#[cfg(not(target_os = "android"))]
mod keyring;
mod location;
#[cfg(not(target_os = "android"))]
mod native_vault;
#[cfg(target_os = "android")]
#[path = "android_vault.rs"]
mod native_vault;
mod nip49_export;
mod owned_vault;
mod ownership;
#[path = "secret_store/receipts.rs"]
mod secret_store;

pub use error::{AccountHomeError, AccountHomeResult};
pub use home::{
    AccountHome, AccountSetupKind, AccountSetupPhase, AccountSetupState, AccountSummary,
    EXTERNAL_SQLCIPHER_SECRET_FILE, ExternalSecretMode, Nip46Removal, Nip46SessionRecord,
    Nip46SessionWrite, NostrAccountImport, ROOT_MUTATION_LOCK_FILE,
};
pub use location::IosOptions;
pub use ownership::{
    AcquiredSecret, SecretClaimMode, SecretCredential, SecretCredentialKind, SecretOrigin,
    SecretReleaseMode, SecretReleaseOutcome,
};
pub use secret_store::{
    AccountSecretStore, CREDENTIAL_STORE_LOCK_FILE, KeychainSecretStore, LocalFileSecretStore,
};
