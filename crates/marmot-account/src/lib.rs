//! Account identity, files and secrets for Marmot.
//!
//! This crate is intentionally small. It owns the local account home: account
//! records, setup journals, signing-key storage and NIP-49 export. The
//! account-device runtime that drives a session over a transport lives in
//! `marmot-session`.

mod error;
mod home;
mod io;
mod keyring;
mod nip49_export;
mod secret_store;

pub use error::{AccountHomeError, AccountHomeResult};
pub use home::{
    AccountHome, AccountSetupKind, AccountSetupPhase, AccountSetupState, AccountSummary,
    EXTERNAL_SQLCIPHER_SECRET_FILE, ExternalSecretMode, NostrAccountImport,
};
pub use secret_store::{AccountSecretStore, KeychainSecretStore, LocalFileSecretStore};
