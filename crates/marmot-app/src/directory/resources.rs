//! What the directory asks the app for. `marmot-app` implements
//! [`DirectoryResources`] over the cache lifecycle it keeps (step 3 of
//! `docs/marmot-architecture/review/brief-directory.md`).

use std::future::Future;

use storage_sqlite::SqliteSharedStorage;
use transport_nostr_peeler::NostrTransportEvent;

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
pub trait DirectoryResources: Clone + Send + Sync + 'static {
    /// Every local account, signed-out ones included, in account-home order.
    fn local_accounts(&self) -> Result<Vec<DirectoryAccount>, DirectoryError>;

    /// The id of the account that holds `label` now. It differs from an
    /// earlier read when the account was removed and the label reused.
    fn account_id_for_label(&self, label: &str) -> Result<String, DirectoryError>;

    /// The caches of every active-signing account, opening any not yet open.
    fn current_caches(&self) -> Result<Vec<DirectoryCache>, DirectoryError>;

    /// One account's cache, opening it if needed.
    fn cache_for_account(
        &self,
        account: &DirectoryAccount,
    ) -> Result<DirectoryCache, DirectoryError>;

    /// The shared public directory tier.
    fn shared_storage(&self) -> Result<SqliteSharedStorage, DirectoryError>;

    /// A stored entry changed, so presentation should refresh that account.
    fn directory_entry_changed(&self, account_id_hex: &str);
}

/// Block lists are account state the app keeps. The sync worker receives
/// their mute-list events with the directory's own and hands the work over.
///
/// Each method returns the work as a future and starts nothing. The worker
/// runs adoptions in its bounded task set and reconciles in one abort-on-drop
/// task, never inline in its event loop, where an account's update lock would
/// park it.
pub trait BlockListSink: Clone + Send + Sync + 'static {
    /// Adopt one live mute-list event for the local account that published it.
    fn adopt_block_list_event(
        &self,
        event: NostrTransportEvent,
    ) -> impl Future<Output = Result<(), DirectoryError>> + Send + 'static;

    /// Fetch and reconcile every local account's block list.
    fn reconcile_block_lists(&self) -> impl Future<Output = ()> + Send + 'static;
}
