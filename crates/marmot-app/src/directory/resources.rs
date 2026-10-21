//! What the directory asks the app for. `marmot-app` implements
//! [`DirectoryResources`] over the cache lifecycle it keeps (step 3 of
//! `docs/marmot-architecture/review/brief-directory.md`).

use storage_sqlite::SqliteSharedStorage;

use super::DirectoryCache;
use super::error::DirectoryError;

/// A local account, as the directory sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryAccount {
    pub account_id_hex: String,
    pub label: String,
    /// The account holds its own signing key.
    pub local_signing: bool,
    /// The account can sign, locally or through an external signer, and is
    /// not signed out.
    pub active_signing: bool,
}

/// The app's resources, handed to the directory as open handles.
///
/// Ask for a cache when it is about to be used. A handle taken before a
/// network step can outlive its account's eviction and keep writing to a
/// closed account's cache.
pub trait DirectoryResources {
    /// Every local account, signed-out ones included, in account-home order.
    fn local_accounts(&self) -> Result<Vec<DirectoryAccount>, DirectoryError>;

    /// The caches of every active-signing account, opening any not yet open.
    fn current_caches(&self) -> Result<Vec<DirectoryCache>, DirectoryError>;

    /// One account's cache, opening it if needed.
    fn cache_for_account(
        &self,
        account: &DirectoryAccount,
    ) -> Result<DirectoryCache, DirectoryError>;

    /// The shared public directory tier.
    fn shared_storage(&self) -> Result<SqliteSharedStorage, DirectoryError>;
}
