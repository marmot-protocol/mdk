//! The directory service. Its methods reach the app only through
//! [`DirectoryResources`]; the directory brief's PR 5 converts the rest of
//! `directory/` to it slice by slice.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use cgka_traits::TransportEndpoint;
use transport_nostr::{
    DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord, MarmotRelayPlane,
};

use super::DirectorySyncHandle;
use super::config::DirectoryConfig;
use super::error::DirectoryError;
use super::ids::parse_account_id_hex;
use super::member_key_packages::MemberKeyPackagePrewarmCache;
use super::resources::DirectoryResources;

/// The user directory: lookups and search over other people's public Nostr
/// data, and the cache that holds it.
#[derive(Clone)]
pub struct Directory<R> {
    pub(super) resources: R,
    pub(super) config: DirectoryConfig,
    pub(super) relay_plane: MarmotRelayPlane,
    pub(super) state: DirectoryState,
}

/// What the directory keeps between calls. Every field is shared, so each
/// [`Directory`] built from one state sees the same values.
#[derive(Clone, Default)]
pub struct DirectoryState {
    /// When each `(account label, cache key)` public event refresh last
    /// finished; see `previews`.
    pub(super) public_event_refreshes: Arc<Mutex<HashMap<String, Instant>>>,
    /// The running sync worker, which a store write asks to rebuild its
    /// subscriptions.
    pub(super) sync_handle: Arc<RwLock<Option<DirectorySyncHandle>>>,
    /// Bounded, process-local composition prewarm. Entries are never durable
    /// directory admission and never reserve or consume a KeyPackage.
    pub(crate) member_key_package_prewarm_cache: Arc<Mutex<MemberKeyPackagePrewarmCache>>,
}

impl<R: DirectoryResources> Directory<R> {
    pub fn new(
        resources: R,
        config: DirectoryConfig,
        relay_plane: MarmotRelayPlane,
        state: DirectoryState,
    ) -> Self {
        Self {
            resources,
            config,
            relay_plane,
            state,
        }
    }

    pub(crate) async fn fetch_events_for_account_ids(
        &self,
        account_ids: &[String],
        kind: u64,
        source_relays: &[TransportEndpoint],
    ) -> Result<Vec<RelayEventRecord>, DirectoryError> {
        let source_relays = self.directory_source_relays(source_relays);
        let account_ids = account_ids
            .iter()
            .map(|account_id| parse_account_id_hex(account_id))
            .collect::<Result<Vec<_>, _>>()?;
        let limit = (account_ids.len() * 4).max(1);
        self.relay_plane
            .fetch_directory_events(
                source_relays,
                vec![DirectoryEventQuery::new(kind, account_ids, limit)],
            )
            .await
            .map_err(|e| {
                DirectoryError::RelayDirectory(format!("fetch user directory events: {e}"))
            })
    }

    /// Accounts to fall back to when a searcher's own web of trust is empty.
    /// See `MarmotAppConfig::directory_search_fallback_seeds`.
    pub(crate) fn directory_search_fallback_seeds(&self) -> &[String] {
        &self.config.fallback_seeds
    }

    /// `source_relays` when given, else the configured directory relays, else
    /// the app's default relays.
    pub(crate) fn directory_source_relays(
        &self,
        source_relays: &[TransportEndpoint],
    ) -> Vec<TransportEndpoint> {
        if !source_relays.is_empty() {
            return source_relays.to_vec();
        }
        if !self.config.directory_relays.is_empty() {
            return self.config.directory_relays.clone();
        }
        self.config.default_relays.clone()
    }
}
