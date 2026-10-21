//! The directory service. Its methods reach the app only through
//! [`DirectoryResources`]; the directory brief's PR 5 converts the rest of
//! `directory/` to it slice by slice.

use super::resources::DirectoryResources;

/// The user directory: lookups and search over other people's public Nostr
/// data, and the cache that holds it.
#[derive(Clone)]
pub struct Directory<R> {
    pub(super) resources: R,
}

impl<R: DirectoryResources> Directory<R> {
    pub fn new(resources: R) -> Self {
        Self { resources }
    }
}
