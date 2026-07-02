//! Thin account-device orchestration for Marmot.
//!
//! This crate is intentionally small. It owns the app-level coordination that
//! sits above `AccountDeviceSession`: transport account activation, transport
//! routing, KeyPackage publication, and publish confirmation or rollback.

mod error;
mod home;
mod io;
mod key_package;
mod keyring;
mod nip49_export;
mod routing;
mod runtime;
mod secret_store;

pub use error::{AccountError, AccountHomeError, AccountHomeResult, AccountResult};
pub use home::{AccountHome, AccountSummary, DEFAULT_KEYCHAIN_SERVICE_NAME};
pub use key_package::{
    KeyPackagePublication, KeyPackagePublishError, KeyPackagePublisher, NoopKeyPackagePublisher,
};
pub use routing::{StaticTransportRouting, TransportRoutingError, TransportRoutingPolicy};
pub use runtime::{
    AccountDeviceEffects, AccountDeviceRuntime, AccountIngestEffects, PendingResolution,
    PublishFailure,
};
pub use secret_store::{AccountSecretStore, KeychainSecretStore, LocalFileSecretStore};
