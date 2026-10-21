//! `MarmotApp`'s public directory methods, as one-line delegates to
//! [`Directory`](crate::directory::Directory). They keep returning `AppError`
//! until callers move to `app.directory()` and these go (PR 7 of
//! `docs/marmot-architecture/review/brief-directory.md`).

use cgka_traits::engine::KeyPackage;

use crate::{AppError, MarmotApp, MemberKeyPackagePrewarmSummary, UserDirectorySearchResult};

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

    /// Resolve a roster as one deterministic set.
    ///
    /// Account aliases are canonicalized and duplicate account ids collapse to
    /// their first input position. Every package is fetched from relays; cached
    /// packages are never a fallback if that lookup fails. On error, the error
    /// belonging to the first unresolved canonical member is returned even if
    /// later relay work completed earlier.
    pub async fn resolve_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<Vec<KeyPackage>, AppError> {
        Ok(self
            .directory()
            .resolve_member_key_packages(member_refs)
            .await?)
    }

    /// Prewarm group composition without reserving or consuming any package.
    /// Success reports relay/metadata readiness only; final Create/Invite
    /// re-fetches packages and enforces the engine's membership policy.
    ///
    /// The roster must also resolve a safe Marmot inbox route for every member;
    /// missing routes return [`AppError::MissingMemberInboxRoute`]. Successfully
    /// discovered routes remain cached even when another member fails readiness.
    /// A malformed current slot publication suppresses older packages here too;
    /// return an error rather than report readiness from superseded material.
    /// Every call fetches packages for a fresh readiness signal; hosts should
    /// debounce composition changes. A later create call can reuse discovery routes,
    /// but fetches KeyPackages again because prewarmed material may have been
    /// consumed in the meantime.
    pub async fn prewarm_group_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<MemberKeyPackagePrewarmSummary, AppError> {
        Ok(self
            .directory()
            .prewarm_group_member_key_packages(member_refs)
            .await?)
    }
}

#[allow(dead_code)]
fn member_resolution_future_is_send(app: &MarmotApp) {
    fn assert_send<T: Send>(_: T) {}
    assert_send(app.resolve_member_key_packages(&[]));
}
