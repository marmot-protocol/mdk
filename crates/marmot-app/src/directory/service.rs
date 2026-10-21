//! The directory service. Its methods reach the app only through
//! [`DirectoryResources`]; the directory brief's PR 5 converts the rest of
//! `directory/` to it slice by slice.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cgka_traits::TransportEndpoint;
use transport_nostr::MarmotRelayPlane;

use super::config::DirectoryConfig;
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
