//! Bounded discovery recovery; a relay copy is not proof of private-key possession.

use crate::error::DirectoryError;
use std::collections::BTreeSet;

use cgka_engine::key_package::KeyPackageRequirements;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::RelayUrl;

use super::Directory;
use super::resources::DirectoryResources;
use crate::DirectoryFreshness;
use crate::published_records::{
    KeyPackageRecoveryEvidence, KeyPackageRecoveryTarget, key_package_deletion_page_full,
    key_package_queries, select_key_packages_from_records, without_revoked_slot_winners,
};
use transport_nostr::{DirectoryEventQuery, DirectoryRelayEventRecord};

const RECOVERY_ENDPOINT_LIMIT: usize = 8;
/// How many revoked candidates recovery replaces before it reports the lookup
/// incomplete. Proving a candidate undeleted spends none of it.
const RECOVERY_CANDIDATE_LIMIT: usize = 12;

pub(super) struct RecoveredKeyPackageRecords {
    /// Admission cutoff shared with final selection: time passing during a
    /// deletion lookup must never admit a different, unchecked candidate.
    pub(super) freshness: DirectoryFreshness,
    pub(super) records: Vec<DirectoryRelayEventRecord>,
    pub(super) cache_evidence: Option<KeyPackageRecoveryEvidence>,
}

pub(super) struct KeyPackageRecoveryRequest<'a> {
    pub(super) account: &'a str,
    pub(super) searched: &'a [TransportEndpoint],
    pub(super) observed: Vec<DirectoryRelayEventRecord>,
    pub(super) primary_complete: bool,
    pub(super) discovery: &'a [TransportEndpoint],
    pub(super) requirements: Option<&'a KeyPackageRequirements>,
    /// Public metadata only. Membership callers must never nominate a cache.
    pub(super) cached_target: Option<KeyPackageRecoveryTarget>,
    /// How many of the best-ranked selected candidates to prove undeleted.
    pub(super) wanted: usize,
}

impl<R: DirectoryResources> Directory<R> {
    /// Recover only after normal selection fails. Never replace a positive
    /// normal lookup with another network stage, or admit cached member bytes.
    pub(super) async fn recover_key_package_records(
        &self,
        request: KeyPackageRecoveryRequest<'_>,
    ) -> Result<RecoveredKeyPackageRecords, DirectoryError> {
        let KeyPackageRecoveryRequest {
            account,
            searched,
            mut observed,
            primary_complete,
            discovery,
            requirements,
            cached_target,
            wanted,
        } = request;
        // Recovery reads more deletion requests only for candidates it
        // proves; it cannot prove what a full page left unread elsewhere.
        if key_package_deletion_page_full(account, &observed) {
            return Err(recovery_incomplete(account));
        }
        let freshness = self.directory_freshness();
        if select_key_packages_from_records(account, &observed, freshness, requirements)
            .is_ok_and(|selection| !selection.value.is_empty())
        {
            return Ok(RecoveredKeyPackageRecords {
                freshness,
                records: observed,
                cache_evidence: None,
            });
        }
        // Primary routes already crossed the maintained 16-endpoint admission
        // gate. Recovery only adds eight distinct safe configured routes.
        let searched = self.relay_plane.retain_safe_discovered_endpoints(
            searched.to_vec(),
            "KeyPackage recovery searched routes",
        );
        // RelayUrl equality ignores an optional root slash, while its display
        // spelling (and TransportEndpoint equality) preserves it. Count relay
        // identities, not spellings, against the supplementary route budget.
        let mut seen = searched
            .iter()
            .filter_map(|endpoint| RelayUrl::parse(endpoint.as_str()).ok())
            .collect::<BTreeSet<_>>();
        let supplementary = self
            .relay_plane
            .retain_safe_discovered_endpoints(discovery.to_vec(), "KeyPackage discovery recovery")
            .into_iter()
            .filter(|endpoint| {
                RelayUrl::parse(endpoint.as_str()).is_ok_and(|relay| seen.insert(relay))
            })
            .take(RECOVERY_ENDPOINT_LIMIT)
            .collect::<Vec<_>>();
        let mut package_coverage = primary_complete;
        if !supplementary.is_empty() {
            match self
                .relay_plane
                .fetch_directory_events_with_completion(
                    supplementary.clone(),
                    key_package_queries(vec![account.to_owned()]),
                )
                .await
            {
                Ok(outcome) => {
                    observed.extend(outcome.records);
                    package_coverage &= outcome.complete;
                }
                Err(_) => package_coverage = false,
            }
        }
        let routes = distinct_recovery_routes(searched.iter().chain(&supplementary));
        // Deletion requests read with the KeyPackages count from the start; a
        // later scoped read that misses one never revives what it covers.
        let mut deletions = observed
            .iter()
            .filter(|record| record.event.kind == 5)
            .cloned()
            .collect::<Vec<_>>();
        // Event ids whose deletion lookup completed without a match.
        let mut proven = BTreeSet::new();
        // The selection being proven. It is redrawn only after a revocation:
        // time passing during a deletion read must never swap in a different
        // candidate.
        let mut targets = None;
        let mut revocations = 0;
        // Every pass proves a candidate not proven before or revokes one, so
        // the selection's size and the revocation limit bound the loop.
        loop {
            let current = match &mut targets {
                Some(current) => current,
                None => {
                    // Preserve every newest slot as a barrier, including
                    // malformed, incompatible and already-revoked replacements.
                    let (records, evidence) = without_revoked_slot_winners(
                        account,
                        observed.clone(),
                        &deletions,
                        freshness,
                    );
                    // A known validation error precedes an incomplete negative
                    // lookup; it never authorizes returning an unproven
                    // usable package.
                    let selection = select_key_packages_from_records(
                        account,
                        &records,
                        freshness,
                        requirements,
                    )?;
                    let mut selected = selection
                        .value
                        .iter()
                        .take(wanted)
                        .map(KeyPackageRecoveryTarget::from_fetched)
                        .collect::<Vec<_>>();
                    if selected.is_empty()
                        && selection.rejected_future
                        && let Some(cached) = cached_target
                            .as_ref()
                            .filter(|target| evidence.allows_target(target))
                    {
                        selected.push(cached.clone());
                    }
                    if selected.is_empty() {
                        if !package_coverage {
                            return Err(recovery_incomplete(account));
                        }
                        return Ok(RecoveredKeyPackageRecords {
                            freshness,
                            records,
                            cache_evidence: Some(evidence),
                        });
                    }
                    targets.insert(selected)
                }
            };
            let Some(target) = current
                .iter()
                .find(|target| !proven.contains(&target.event_id))
                .cloned()
            else {
                return Ok(proven_records(
                    account, observed, &deletions, freshness, &proven,
                ));
            };
            if !package_coverage || routes.is_empty() || revocations == RECOVERY_CANDIDATE_LIMIT {
                return Err(recovery_incomplete(account));
            }
            let queries = vec![
                DirectoryEventQuery::deletion_reference(
                    account,
                    'e',
                    target.event_id.clone(),
                    None,
                ),
                DirectoryEventQuery::deletion_reference(
                    account,
                    'a',
                    format!("30443:{account}:{}", target.slot),
                    Some(target.created_at),
                ),
            ];
            let mut deletion_coverage = true;
            let mut revoked = false;
            // Separate e/a existence filters (OR), each limit one: unrelated
            // post deletions cannot consume the proof's bounded result budget.
            for endpoints in routes.chunks(RECOVERY_ENDPOINT_LIMIT) {
                match self
                    .relay_plane
                    .fetch_directory_events_with_completion(endpoints.to_vec(), queries.clone())
                    .await
                {
                    Ok(outcome) => {
                        deletion_coverage &= outcome.complete;
                        deletions.extend(outcome.records);
                    }
                    Err(_) => deletion_coverage = false,
                }
                let (_, gathered) =
                    without_revoked_slot_winners(account, observed.clone(), &deletions, freshness);
                // A verified positive is sufficient to reject a candidate,
                // even if another route failed or the existence limit was hit.
                if !gathered.allows_target(&target) {
                    revoked = true;
                    break;
                }
            }
            if revoked {
                revocations += 1;
                targets = None;
                continue;
            }
            if !deletion_coverage {
                return Err(recovery_incomplete(account));
            }
            proven.insert(target.event_id);
        }
    }
}

/// Records whose only fresh candidates are the `proven` ones. Final admission
/// revalidates MLS lifetime on the real wall clock. It may reject a proven
/// identity after a slow deletion read, but must never select a different
/// fresh slot whose deletion was not read. Rejected-future metadata stays for
/// the diagnostic cache fallback, whose exact target was checked.
fn proven_records(
    account: &str,
    observed: Vec<DirectoryRelayEventRecord>,
    deletions: &[DirectoryRelayEventRecord],
    freshness: DirectoryFreshness,
    proven: &BTreeSet<String>,
) -> RecoveredKeyPackageRecords {
    let (mut records, evidence) =
        without_revoked_slot_winners(account, observed, deletions, freshness);
    records.retain(|record| !freshness.accepts(record) || proven.contains(&record.event.id));
    RecoveredKeyPackageRecords {
        freshness,
        records,
        cache_evidence: Some(evidence),
    }
}

fn distinct_recovery_routes<'a>(
    endpoints: impl IntoIterator<Item = &'a TransportEndpoint>,
) -> Vec<TransportEndpoint> {
    let mut seen = BTreeSet::new();
    endpoints
        .into_iter()
        .filter(|endpoint| RelayUrl::parse(endpoint.as_str()).is_ok_and(|relay| seen.insert(relay)))
        .cloned()
        .collect()
}

/// Lookup or deletion coverage was not established for this account.
fn recovery_incomplete(account: &str) -> DirectoryError {
    DirectoryError::DirectoryLookupIncomplete(account.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_recovery_deletion_routes_deduplicate_optional_root_slashes() {
        let routes = [
            TransportEndpoint("wss://outbox.example".into()),
            TransportEndpoint("wss://outbox.example/".into()),
            TransportEndpoint("wss://directory.example/".into()),
            TransportEndpoint("wss://directory.example".into()),
        ];
        assert_eq!(
            distinct_recovery_routes(&routes),
            vec![routes[0].clone(), routes[2].clone()]
        );
    }
}
