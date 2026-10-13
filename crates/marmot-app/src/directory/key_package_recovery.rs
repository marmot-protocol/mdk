//! Bounded discovery recovery; a relay copy is not proof of private-key possession.

use std::collections::BTreeSet;

use cgka_engine::key_package::KeyPackageRequirements;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::RelayUrl;
use transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE;

use crate::key_package_records::{
    KeyPackageRecoveryEvidence, KeyPackageRecoveryTarget, MemberKeyPackageExclusions,
    preferred_fresh_key_package_from_records, validate_member_key_package_candidates,
    without_revoked_slot_winners,
};
use crate::relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord};
use crate::{AppError, DirectoryFreshness, MarmotApp};

const RECOVERY_ENDPOINT_LIMIT: usize = 8;
const RECOVERY_CANDIDATE_LIMIT: usize = 32;
// Two existence filters per candidate; keep each REQ at ten filters rather
// than relying on a relay accepting an unbounded OR filter list.
const RECOVERY_PROOF_CANDIDATES_PER_BATCH: usize = 5;

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
    pub(super) all_devices: bool,
    pub(super) exclusions: &'a MemberKeyPackageExclusions,
}

impl MarmotApp {
    /// Member lookups discover supplementary slots and reject observed deletions.
    /// Superseded-invite recovery additionally requires complete coverage.
    /// Single-package diagnostics recover only after normal selection
    /// fails. Neither path admits cached bytes as membership authority.
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
            all_devices,
            exclusions,
        } = request;
        let freshness = self.directory_freshness();
        let strict_coverage = !all_devices || exclusions.obligations.is_some();
        if !all_devices
            && preferred_fresh_key_package_from_records(account, &observed, freshness, requirements)
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
            let query =
                DirectoryEventQuery::new(KIND_MARMOT_KEY_PACKAGE, vec![account.to_owned()], 32);
            let query = if all_devices {
                query.bounded_key_package_prefix()
            } else {
                query
            };
            match self
                .relay_plane
                .fetch_directory_events_with_completion(supplementary.clone(), vec![query])
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
        let mut validated = all_devices.then(|| {
            validate_member_key_package_candidates(account, &observed, freshness, requirements)
        });
        let mut deletions = Vec::new();
        let mut checked = BTreeSet::new();
        let mut attempted = BTreeSet::new();
        loop {
            // Preserve every newest slot as a barrier, including malformed,
            // incompatible and already-revoked replacements.
            let (records, evidence) =
                without_revoked_slot_winners(account, observed.clone(), &deletions, freshness);
            // A known validation error precedes an incomplete negative lookup;
            // it never authorizes returning an unproven usable package.
            let (candidates, rejected_future) = if all_devices {
                let allowed = records
                    .iter()
                    .map(|record| record.event.id.as_str())
                    .collect::<BTreeSet<_>>();
                let selection = validated
                    .as_mut()
                    .expect("all-device candidates validated")
                    .select(
                        |candidate| allowed.contains(candidate.key_package_event_id.as_str()),
                        exclusions,
                    )?;
                (selection.value, selection.rejected_future)
            } else {
                let selection = preferred_fresh_key_package_from_records(
                    account,
                    &records,
                    freshness,
                    requirements,
                )?;
                (
                    selection
                        .value
                        .into_iter()
                        .map(|selected| selected.fetched)
                        .collect(),
                    selection.rejected_future,
                )
            };
            let mut targets = candidates
                .iter()
                .filter(|candidate| !checked.contains(&candidate.key_package_event_id))
                .map(KeyPackageRecoveryTarget::from_fetched)
                .collect::<Vec<_>>();
            if targets.is_empty()
                && candidates.is_empty()
                && rejected_future
                && let Some(target) = cached_target.as_ref().filter(|target| {
                    !checked.contains(&target.event_id) && evidence.allows_target(target)
                })
            {
                targets.push(target.clone());
            }
            if targets.is_empty() {
                if !package_coverage && (strict_coverage || observed.is_empty()) {
                    return Err(recovery_incomplete());
                }
                return Ok(RecoveredKeyPackageRecords {
                    freshness,
                    records: records
                        .into_iter()
                        .filter(|record| {
                            !freshness.accepts(record) || checked.contains(&record.event.id)
                        })
                        .collect(),
                    cache_evidence: Some(evidence),
                });
            }
            attempted.extend(targets.iter().map(|target| target.event_id.clone()));
            if attempted.len() > RECOVERY_CANDIDATE_LIMIT
                || (strict_coverage && (!package_coverage || routes.is_empty()))
            {
                return Err(recovery_incomplete());
            }
            let mut deletion_coverage = true;
            for batch in targets.chunks(RECOVERY_PROOF_CANDIDATES_PER_BATCH) {
                let queries = batch
                    .iter()
                    .flat_map(|target| {
                        // Separate e/a existence filters (OR), each limit one:
                        // unrelated deletions cannot consume a candidate's budget.
                        [
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
                        ]
                    })
                    .collect::<Vec<_>>();
                let mut batch_complete = true;
                for endpoints in routes.chunks(RECOVERY_ENDPOINT_LIMIT) {
                    match self
                        .relay_plane
                        .fetch_directory_events_with_completion(endpoints.to_vec(), queries.clone())
                        .await
                    {
                        Ok(outcome) => {
                            batch_complete &= outcome.complete;
                            deletions.extend(outcome.records);
                        }
                        Err(_) => batch_complete = false,
                    }
                }
                deletion_coverage &= batch_complete;
                if batch_complete || !strict_coverage {
                    checked.extend(batch.iter().map(|target| target.event_id.clone()));
                }
            }
            let (records, evidence) =
                without_revoked_slot_winners(account, observed.clone(), &deletions, freshness);
            if targets.iter().any(|target| !evidence.allows_target(target)) {
                // A verified positive rejects its slot even when its existence
                // filter saturated. Re-select only after a revocation, then
                // prove any unchecked survivors/replacement winners together.
                continue;
            }
            if strict_coverage && !deletion_coverage {
                return Err(recovery_incomplete());
            }
            // No winner changed: candidates satisfy this path's evidence policy.
            // Do not re-select the whole set just to discover it is unchanged.
            return Ok(RecoveredKeyPackageRecords {
                freshness,
                records: records
                    .into_iter()
                    .filter(|record| {
                        !freshness.accepts(record) || checked.contains(&record.event.id)
                    })
                    .collect(),
                cache_evidence: Some(evidence),
            });
        }
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
