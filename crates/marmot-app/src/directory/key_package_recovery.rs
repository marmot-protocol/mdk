//! Bounded discovery recovery; a relay copy is not proof of private-key possession.

use std::collections::BTreeSet;

use cgka_engine::key_package::KeyPackageRequirements;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::RelayUrl;
use transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE;

use crate::key_package_records::{
    KeyPackageRecoveryEvidence, KeyPackageRecoveryTarget, preferred_fresh_key_package_from_records,
    without_revoked_slot_winners,
};
use crate::relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord};
use crate::{AppError, DirectoryFreshness, MarmotApp};

const RECOVERY_ENDPOINT_LIMIT: usize = 8;
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
}

impl MarmotApp {
    /// Recover only after normal selection fails. Never replace a positive
    /// normal lookup with another network stage, or admit cached member bytes.
    pub(super) async fn recover_key_package_records(
        &self,
        request: KeyPackageRecoveryRequest<'_>,
    ) -> Result<RecoveredKeyPackageRecords, AppError> {
        let KeyPackageRecoveryRequest {
            account,
            searched,
            mut observed,
            primary_complete,
            discovery,
            requirements,
            cached_target,
        } = request;
        let freshness = self.directory_freshness();
        if preferred_fresh_key_package_from_records(account, &observed, freshness, requirements)
            .is_ok_and(|selection| selection.value.is_some())
        {
            return Ok(RecoveredKeyPackageRecords {
                freshness,
                records: observed,
                cache_evidence: None,
            });
        }
        // Primary routes already crossed the maintained 16-endpoint admission
        // gate. Recovery only adds eight distinct safe configured routes.
        let searched = self.retain_safe_discovered_endpoints(
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
                    vec![DirectoryEventQuery::new(
                        KIND_MARMOT_KEY_PACKAGE,
                        vec![account.to_owned()],
                        12,
                    )],
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
        let mut deletions = Vec::new();
        for round in 0..=RECOVERY_CANDIDATE_LIMIT {
            // Preserve every newest slot as a barrier, including malformed,
            // incompatible and already-revoked replacements.
            let (records, evidence) =
                without_revoked_slot_winners(account, observed.clone(), &deletions, freshness);
            // A known validation error precedes an incomplete negative lookup;
            // it never authorizes returning an unproven usable package.
            let selection = preferred_fresh_key_package_from_records(
                account,
                &records,
                freshness,
                requirements,
            )?;
            let target = selection
                .value
                .as_ref()
                .map(|selected| KeyPackageRecoveryTarget::from_fetched(&selected.fetched))
                .or_else(|| {
                    selection
                        .rejected_future
                        .then_some(cached_target.as_ref())
                        .flatten()
                        .filter(|target| evidence.allows_target(target))
                        .cloned()
                });
            let Some(target) = target else {
                if !package_coverage {
                    return Err(recovery_incomplete());
                }
                return Ok(RecoveredKeyPackageRecords {
                    freshness,
                    records,
                    cache_evidence: Some(evidence),
                });
            };
            if round == RECOVERY_CANDIDATE_LIMIT || !package_coverage || routes.is_empty() {
                return Err(recovery_incomplete());
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
                continue;
            }
            if !deletion_coverage {
                return Err(recovery_incomplete());
            }
            let (mut records, evidence) =
                without_revoked_slot_winners(account, observed, &deletions, freshness);
            // Final admission revalidates MLS lifetime on the real wall clock.
            // It may reject this identity after a slow deletion read, but must
            // never select a different fresh slot whose deletion was not read.
            // Preserve rejected-future metadata for the existing diagnostic
            // cache fallback, whose exact target was checked above.
            records
                .retain(|record| !freshness.accepts(record) || record.event.id == target.event_id);
            return Ok(RecoveredKeyPackageRecords {
                freshness,
                records,
                cache_evidence: Some(evidence),
            });
        }
        Err(recovery_incomplete())
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

fn recovery_incomplete() -> AppError {
    AppError::RelayDirectory(
        "invitation key recovery could not establish complete lookup and deletion coverage".into(),
    )
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
