//! `MarmotApp`'s public directory methods, as one-line delegates to
//! [`Directory`](crate::directory::Directory). They keep returning `AppError`
//! until callers move to `app.directory()` and these go (PR 7 of
//! `docs/marmot-architecture/review/brief-directory.md`).

use crate::{AppError, MarmotApp, UserDirectorySearchResult};

impl MarmotApp {
    /// Search all cached public identities, independent of social-graph reachability.
    /// This does no relay work or group-membership reads. Follow attribution is
    /// relative to `searcher_account_id_hex`; local labels and private nicknames
    /// never participate. A zero limit returns no results. Call off the UI thread.
    pub fn search_cached_users(
        &self,
        searcher_account_id_hex: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<UserDirectorySearchResult>, AppError> {
        Ok(self
            .directory()
            .search_cached_users(searcher_account_id_hex, query, limit)?)
    }
}
