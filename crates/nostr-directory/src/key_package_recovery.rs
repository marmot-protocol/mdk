//! Bounded discovery recovery; a relay copy is not proof of private-key possession.

use crate::error::DirectoryError;
use crate::member_key_packages::key_package_requirements_are_incompatible;
use std::cmp::Ordering;
use std::collections::BTreeSet;

use cgka_engine::key_package::KeyPackageRequirements;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::RelayUrl;

use super::Directory;
use super::resources::DirectoryResources;
use crate::published_records::{
    KeyPackageJournalFence, KeyPackageRecoveryEvidence, KeyPackageRecoveryTarget,
    key_package_queries, key_package_read_page_full, newest_publication_first, package_is_deleted,
    select_fenced_key_packages, verified_deletions, without_revoked_slot_winners,
};
use crate::{DirectoryFreshness, FetchedKeyPackage};
use transport_nostr::{DirectoryEventQuery, DirectoryFetchOutcome, DirectoryRelayEventRecord};
use transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE;

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
    /// Every KeyPackage read behind `records` completed.
    pub(super) complete: bool,
}

impl RecoveredKeyPackageRecords {
    /// The final selection, which revalidates each package on the wall clock.
    /// A non-empty selection may still leave out a device (D12). After a
    /// complete read, an empty one or a refusal is the verdict, unless
    /// `fence` knows a publication the records lack.
    pub(super) fn select(
        &self,
        account: &str,
        requirements: Option<&KeyPackageRequirements>,
        fence: Option<&KeyPackageJournalFence>,
    ) -> Result<Vec<FetchedKeyPackage>, DirectoryError> {
        match select_fenced_key_packages(
            account,
            &self.records,
            self.freshness,
            requirements,
            fence,
        ) {
            Ok(selection) if !selection.value.is_empty() => Ok(selection.value),
            // Losing an incomplete read's package to revalidation says
            // nothing about what the recipient published.
            _ if !self.complete => Err(recovery_incomplete(account)),
            selection => selection?.into_value_or_missing(account),
        }
    }
}

pub(super) struct KeyPackageRecoveryRequest<'a> {
    pub(super) account: &'a str,
    pub(super) searched: &'a [TransportEndpoint],
    pub(super) observed: Vec<DirectoryRelayEventRecord>,
    /// What an earlier read in this lookup returned. Its packages can be used
    /// and its replacements and deletions count, but a relay may since have
    /// withdrawn a package, so one no completed read served again decides
    /// nothing.
    pub(super) hints: Vec<DirectoryRelayEventRecord>,
    pub(super) primary_complete: bool,
    pub(super) discovery: &'a [TransportEndpoint],
    pub(super) requirements: Option<&'a KeyPackageRequirements>,
    /// Replacements and deletions the journal already knows.
    pub(super) fence: Option<&'a KeyPackageJournalFence>,
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
            hints,
            primary_complete,
            discovery,
            requirements,
            fence,
            cached_target,
            wanted,
        } = request;
        // What completed reads served, which only hints need.
        let mut served = if primary_complete && !hints.is_empty() {
            observed.clone()
        } else {
            Vec::new()
        };
        observed.extend(hints.iter().cloned());
        // A full page of KeyPackages or deletion requests hides what lies
        // past it; recovery's targeted reads cannot show that either.
        if key_package_read_page_full(account, &observed) {
            return Err(recovery_incomplete(account));
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
        let freshness = self.directory_freshness();
        // What the read found is used even when the read was incomplete:
        // every device is sought, not guaranteed (mdk#2628, D12).
        if select_fenced_key_packages(account, &observed, freshness, requirements, fence)
            .is_ok_and(|selection| !selection.value.is_empty())
        {
            // Losing this package decides nothing if a supplementary read was
            // skipped or an earlier read's package went unserved.
            let complete = primary_complete
                && supplementary.is_empty()
                && !unserved_hint(account, &hints, &served, &observed, fence, freshness);
            return Ok(RecoveredKeyPackageRecords {
                freshness,
                records: observed,
                cache_evidence: None,
                complete,
            });
        }
        let mut package_coverage = primary_complete;
        // The caller's fence predates every read below. Each selection after
        // a read uses a journal snapshot taken after it, so a replacement or
        // deletion another lookup recorded meanwhile still counts.
        let mut refreshed = None;
        if !supplementary.is_empty() {
            let outcome = self
                .relay_plane
                .fetch_directory_events_with_completion(
                    supplementary.clone(),
                    key_package_queries(vec![account.to_owned()]),
                )
                .await
                .map_err(DirectoryError::RelayDirectory)?;
            // Callers journal the primary read; journal only this reply.
            refreshed = self
                .journal_and_refresh_fence(account, &outcome.records, fence)
                .await?;
            if outcome.complete && !hints.is_empty() {
                served.extend(outcome.records.iter().cloned());
            }
            observed.extend(outcome.records);
            package_coverage &= outcome.complete;
        }
        // Evaluated at each verdict: a deletion request a later read returns
        // accounts for an earlier read's package too.
        let verdict_coverage =
            |deletions: &[DirectoryRelayEventRecord], fence: Option<&KeyPackageJournalFence>| {
                package_coverage
                    && !unserved_hint(account, &hints, &served, deletions, fence, freshness)
            };
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
                    // A compatibility refusal describes the recipient's
                    // available packages and requires complete coverage.
                    let journal = refreshed.as_ref().or(fence);
                    let selection = match select_fenced_key_packages(
                        account,
                        &records,
                        freshness,
                        requirements,
                        journal,
                    ) {
                        Err(DirectoryError::KeyPackageRequirements(error))
                            if !verdict_coverage(&deletions, journal)
                                && key_package_requirements_are_incompatible(&error) =>
                        {
                            return Err(recovery_incomplete(account));
                        }
                        result => result?,
                    };
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
                        // Absence is a verdict too, with the same coverage.
                        if !verdict_coverage(&deletions, journal) {
                            return Err(recovery_incomplete(account));
                        }
                        return Ok(RecoveredKeyPackageRecords {
                            freshness,
                            records,
                            cache_evidence: Some(evidence),
                            complete: true,
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
                let complete = verdict_coverage(&deletions, refreshed.as_ref().or(fence));
                return Ok(proven_records(
                    account, observed, &deletions, freshness, &proven, complete,
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
                let outcome = self
                    .relay_plane
                    .fetch_directory_events_with_completion(endpoints.to_vec(), queries.clone())
                    .await
                    .map_err(DirectoryError::RelayDirectory)?;
                deletion_coverage &= self
                    .record_recovery_deletion_outcome(account, outcome, &mut deletions)
                    .await?;
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
                // The deletion read already journaled what it found.
                refreshed = self.journal_and_refresh_fence(account, &[], fence).await?;
                continue;
            }
            if !deletion_coverage {
                return Err(recovery_incomplete(account));
            }
            proven.insert(target.event_id);
        }
    }

    /// Journals `records`, then rereads the account's fence when the caller
    /// supplied one.
    async fn journal_and_refresh_fence(
        &self,
        account: &str,
        records: &[DirectoryRelayEventRecord],
        fence: Option<&KeyPackageJournalFence>,
    ) -> Result<Option<KeyPackageJournalFence>, DirectoryError> {
        if fence.is_none() {
            self.journal_key_package_records(account, records).await?;
            return Ok(None);
        }
        Ok(Some(KeyPackageJournalFence::new(
            self.journal_and_read_key_package_evidence(account, records)
                .await?,
        )))
    }

    async fn record_recovery_deletion_outcome(
        &self,
        account: &str,
        outcome: DirectoryFetchOutcome,
        deletions: &mut Vec<DirectoryRelayEventRecord>,
    ) -> Result<bool, DirectoryError> {
        // Scoped discoveries are not included in the returned package records.
        // Persist even incomplete reads before selection or a later error can
        // discard their positive deletion evidence.
        self.journal_scoped_deletion_records(account, &outcome.records)
            .await?;
        deletions.extend(outcome.records);
        Ok(outcome.complete)
    }
}

/// Records whose only fresh candidates are the `proven` ones. Final admission
/// revalidates MLS lifetime on the real wall clock. It may reject a proven
/// identity after a slow deletion read, but must never select a different
/// fresh slot whose deletion was not read. Rejected-future metadata stays for
/// the diagnostic cache fallback, whose exact target was checked. Losing the
/// proven candidates is a verdict only with `complete` coverage and no other
/// fresh package left unproven here.
fn proven_records(
    account: &str,
    observed: Vec<DirectoryRelayEventRecord>,
    deletions: &[DirectoryRelayEventRecord],
    freshness: DirectoryFreshness,
    proven: &BTreeSet<String>,
    complete: bool,
) -> RecoveredKeyPackageRecords {
    let (mut records, evidence) =
        without_revoked_slot_winners(account, observed, deletions, freshness);
    let unproven = |record: &DirectoryRelayEventRecord| {
        freshness.accepts(record) && !proven.contains(&record.event.id)
    };
    // Every record left is one of the account's KeyPackages.
    let alternate = records.iter().any(unproven);
    records.retain(|record| !unproven(record));
    RecoveredKeyPackageRecords {
        freshness,
        records,
        cache_evidence: Some(evidence),
        complete: complete && !alternate,
    }
}

/// Whether some package in `hints` that is still a candidate has no
/// completed read serving it or a publication that replaces it in its slot.
/// Confirmation uses selection's freshness boundary and slot order. A hint
/// that a verified deletion request among `observed` covers, or that the
/// journal bars, is no candidate and needs no confirmation.
fn unserved_hint(
    account: &str,
    hints: &[DirectoryRelayEventRecord],
    served: &[DirectoryRelayEventRecord],
    observed: &[DirectoryRelayEventRecord],
    fence: Option<&KeyPackageJournalFence>,
    freshness: DirectoryFreshness,
) -> bool {
    if hints.is_empty() {
        return false;
    }
    let package = |record: &&DirectoryRelayEventRecord| {
        record.event.kind == KIND_MARMOT_KEY_PACKAGE
            && record.event.pubkey == account
            && freshness.accepts(record)
    };
    let deletions = verified_deletions(account, observed);
    hints.iter().filter(package).any(|hint| {
        let slot = hint.event.tag_value("d").unwrap_or_default();
        let (id, created_at) = (hint.event.id.as_str(), hint.event.created_at);
        if package_is_deleted(account, id, slot, created_at, &deletions)
            || fence.is_some_and(|fence| !fence.allows(id, slot, created_at))
        {
            return false;
        }
        !served.iter().filter(package).any(|record| {
            // A package without a slot is replaced by nothing else.
            if slot.is_empty() {
                return record.event.id == id;
            }
            record.event.tag_value("d") == Some(slot)
                && newest_publication_first(&record.event, created_at, id) != Ordering::Greater
        })
    })
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
    use crate::{DirectoryAccount, DirectoryCache, DirectoryConfig, DirectoryState};
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    use std::time::Duration;
    use storage_sqlite::SqliteSharedStorage;
    use transport_nostr::MarmotRelayPlane;
    use transport_nostr_peeler::NostrTransportEvent;

    #[derive(Clone)]
    struct JournalResources(SqliteSharedStorage);

    impl DirectoryResources for JournalResources {
        fn local_accounts(&self) -> Result<Vec<DirectoryAccount>, DirectoryError> {
            Ok(Vec::new())
        }

        fn account_id_for_label(&self, _: &str) -> Result<String, DirectoryError> {
            unreachable!("deletion journaling does not resolve account labels")
        }

        fn current_caches(&self) -> Result<Vec<DirectoryCache>, DirectoryError> {
            Ok(Vec::new())
        }

        fn cache_for_account(
            &self,
            _: &DirectoryAccount,
        ) -> Result<DirectoryCache, DirectoryError> {
            unreachable!("deletion journaling does not open account caches")
        }

        fn shared_storage(&self) -> Result<SqliteSharedStorage, DirectoryError> {
            Ok(self.0.clone())
        }

        fn directory_entry_changed(&self, _: &str) {}

        fn account_key_package_published(&self, _: &str) {}
    }

    #[tokio::test]
    async fn scoped_deletion_outcome_is_journaled_even_when_incomplete() {
        let shared = SqliteSharedStorage::in_memory().unwrap();
        let plane = MarmotRelayPlane::full_history();
        let directory = Directory::new(
            JournalResources(shared.clone()),
            DirectoryConfig {
                directory_relays: Vec::new(),
                default_relays: Vec::new(),
                max_future_skew: Duration::from_secs(60),
                open_ranking: None,
                fallback_seeds: Vec::new(),
                http_builder: Ok,
                test_clock: None,
            },
            plane.clone(),
            DirectoryState::default(),
        );
        let keys = Keys::generate();
        let account = keys.public_key().to_hex();
        let deleted_event_id = "ab".repeat(32);
        let signed = EventBuilder::new(Kind::from(5), "")
            .tags([Tag::custom("e", [deleted_event_id.clone()])])
            .finalize(&keys)
            .unwrap();
        let record = DirectoryRelayEventRecord {
            endpoints: vec![TransportEndpoint("wss://outbox.example".into())],
            event: NostrTransportEvent::from_nostr_event(&signed).unwrap(),
        };
        let mut deletions = Vec::new();

        let complete = directory
            .record_recovery_deletion_outcome(
                &account,
                DirectoryFetchOutcome {
                    records: vec![record.clone()],
                    complete: false,
                    complete_endpoints: Vec::new(),
                },
                &mut deletions,
            )
            .await
            .unwrap();

        assert!(!complete);
        assert_eq!(deletions, vec![record.clone()]);
        let recovered = proven_records(
            &account,
            Vec::new(),
            &deletions,
            directory.directory_freshness(),
            &BTreeSet::new(),
            true,
        );
        assert!(recovered.records.is_empty());
        let barriers = shared.public_key_package_barriers(&account).unwrap();
        assert_eq!(barriers.len(), 1);
        assert_eq!(barriers[0].event_id_hex, record.event.id);
        assert_eq!(
            barriers[0].deleted_event_id.as_deref(),
            Some(deleted_event_id.as_str())
        );
        shared.close().unwrap();
        plane.shutdown().await;
    }

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
