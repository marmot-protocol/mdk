//! The account's own KeyPackage inventory: records built from fetched
//! KeyPackages, relay-history deduplication, the merge with local state, and
//! publish-endpoint selection. They hold no `MarmotApp` state.
//!
//! Parsing, validation and selection of other accounts' relay lists and
//! KeyPackages live in `nostr_directory::published_records`.

use cgka_traits::TransportEndpoint;
#[cfg(test)]
use std::collections::BTreeSet;

use crate::error::AppError;
use crate::{
    AccountKeyPackageInventoryEntry, AccountKeyPackageLocalState, AccountKeyPackageRecord,
    AccountKeyPackageRelayEvent, AccountRelayListBootstrap, FetchedKeyPackage, push_unique_strings,
};

// Names the test module below reaches through `super::*`; the code they test
// moved to `nostr_directory::published_records`.
#[cfg(test)]
#[allow(unused_imports)]
use crate::error::MissingKeyPackageReason;
#[cfg(test)]
#[allow(unused_imports)]
use crate::{AccountRelayListStatus, DirectoryKeyPackage, UserDirectoryRecord};
#[cfg(test)]
#[allow(unused_imports)]
use cgka_traits::engine::KeyPackage;
#[cfg(test)]
#[allow(unused_imports)]
use transport_nostr::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};
#[cfg(test)]
#[allow(unused_imports)]
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};
#[cfg(test)]
#[allow(unused_imports)]
use transport_nostr_peeler::NostrTransportEvent;

// The other-account half moved to `nostr_directory::published_records`. The
// app's own KeyPackage paths still decode records through these two, and the
// tests below still cover the rest through `super::*`.
#[cfg(test)]
pub(crate) use nostr_directory::{
    fresh_or_cached_key_package, latest_fresh_key_package_from_records,
    preferred_fresh_key_package_from_records, relay_list_queries, relay_list_status_from_records,
    require_key_package_tag, require_multi_value_key_package_tag_matches,
    validated_cached_key_package,
};
pub(crate) use nostr_directory::{
    key_package_from_hex_with_optional_source, key_package_from_record,
};

pub(crate) fn account_key_package_record_from_fetched(
    fetched: FetchedKeyPackage,
) -> AccountKeyPackageRecord {
    AccountKeyPackageRecord {
        account_label: None,
        account_id_hex: fetched.account_id_hex,
        key_package_id: fetched.key_package_id,
        key_package_ref_hex: fetched.key_package_ref_hex,
        key_package_event_id: fetched.key_package_event_id,
        published_at: fetched.created_at,
        key_package_bytes: fetched.key_package.bytes().len(),
        source_relays: fetched.source_relays,
        local: false,
        relay: true,
    }
}

/// Kind 30443 is an explicit precondition of the production fetch path. The
/// pure slot key is `(account_id_hex, key_package_id)` and is only invented
/// when both identities are nonempty.
fn relay_slot_key(record: &AccountKeyPackageRecord) -> Option<(&str, &str)> {
    if record.account_id_hex.is_empty() || record.key_package_id.is_empty() {
        None
    } else {
        Some((
            record.account_id_hex.as_str(),
            record.key_package_id.as_str(),
        ))
    }
}

fn relay_event_id_cmp(left: &AccountKeyPackageRecord, right: &AccountKeyPackageRecord) -> bool {
    right.published_at > left.published_at
        || (right.published_at == left.published_at
            && right.key_package_event_id < left.key_package_event_id)
}

/// Deduplicate validated relay rows by exact event ID and union their
/// endpoint observations. Package fields stay with the event that owns them.
fn deduplicate_relay_key_package_records(
    records: impl IntoIterator<Item = AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRecord> {
    let mut records = records.into_iter().collect::<Vec<_>>();
    for record in &mut records {
        record.source_relays.sort();
        record.source_relays.dedup();
    }
    records.sort_by(record_identity_cmp);
    let mut deduped = Vec::<AccountKeyPackageRecord>::new();
    for record in records {
        if let Some(existing) = deduped.iter_mut().find(|existing| {
            !record.key_package_event_id.is_empty()
                && record.key_package_event_id == existing.key_package_event_id
        }) {
            push_unique_strings(&mut existing.source_relays, record.source_relays);
            existing.source_relays.sort();
        } else {
            deduped.push(record);
        }
    }
    deduped
}

fn current_relay_event_ids(
    records: &[AccountKeyPackageRecord],
) -> std::collections::BTreeSet<String> {
    let mut winners = std::collections::BTreeMap::<(&str, &str), &AccountKeyPackageRecord>::new();
    let mut current = std::collections::BTreeSet::new();
    for record in records {
        let Some(slot) = relay_slot_key(record) else {
            if !record.key_package_event_id.is_empty() {
                current.insert(record.key_package_event_id.clone());
            }
            continue;
        };
        match winners.get(&slot) {
            Some(winner) if !relay_event_id_cmp(winner, record) => {}
            _ => {
                winners.insert(slot, record);
            }
        }
    }
    current.extend(
        winners
            .into_values()
            .map(|record| record.key_package_event_id.clone()),
    );
    current
}

fn relay_history_sort(
    left: &AccountKeyPackageRelayEvent,
    right: &AccountKeyPackageRelayEvent,
) -> std::cmp::Ordering {
    right
        .created_at
        .cmp(&left.created_at)
        .then_with(|| left.key_package_event_id.cmp(&right.key_package_event_id))
        .then_with(|| left.account_id_hex.cmp(&right.account_id_hex))
        .then_with(|| left.key_package_id.cmp(&right.key_package_id))
}

pub(crate) fn account_key_package_relay_events_from_records(
    records: impl IntoIterator<Item = AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRelayEvent> {
    let relay_records =
        deduplicate_relay_key_package_records(records.into_iter().filter(|record| record.relay));
    let current_ids = current_relay_event_ids(&relay_records);
    let mut events = relay_records
        .into_iter()
        .map(|record| AccountKeyPackageRelayEvent {
            is_current: current_ids.contains(&record.key_package_event_id),
            account_id_hex: record.account_id_hex,
            key_package_id: record.key_package_id,
            key_package_ref_hex: record.key_package_ref_hex,
            key_package_event_id: record.key_package_event_id,
            created_at: record.published_at,
            key_package_bytes: record.key_package_bytes,
            source_relays: record.source_relays,
        })
        .collect::<Vec<_>>();
    events.sort_by(relay_history_sort);
    events
}

fn current_relay_key_package_records(
    records: impl IntoIterator<Item = AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRecord> {
    let relay_records = deduplicate_relay_key_package_records(records);
    let current_ids = current_relay_event_ids(&relay_records);
    relay_records
        .into_iter()
        .filter(|record| {
            current_ids.contains(&record.key_package_event_id)
                || record.key_package_event_id.is_empty()
        })
        .collect()
}

fn overlay_local_key_package_records(
    mut merged: Vec<AccountKeyPackageRecord>,
    locals: impl IntoIterator<Item = AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRecord> {
    for record in locals {
        let matching_relay_indexes = merged
            .iter()
            .enumerate()
            .filter_map(|(index, existing)| {
                ((!record.key_package_event_id.is_empty()
                    && record.key_package_event_id == existing.key_package_event_id)
                    || (record.key_package_event_id.is_empty()
                        && !record.key_package_ref_hex.is_empty()
                        && record.key_package_ref_hex == existing.key_package_ref_hex))
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        if matching_relay_indexes.is_empty() {
            if let Some(existing) = merged.iter_mut().find(|existing| {
                existing.local
                    && !existing.relay
                    && ((!record.key_package_ref_hex.is_empty()
                        && record.key_package_ref_hex == existing.key_package_ref_hex)
                        || (record.key_package_ref_hex.is_empty()
                            && existing.key_package_ref_hex.is_empty()
                            && record.key_package_event_id.is_empty()
                            && existing.key_package_event_id.is_empty()
                            && record.key_package_id == existing.key_package_id))
            }) {
                merge_record_fields(existing, &record);
            } else {
                merged.push(record);
            }
        } else {
            for index in matching_relay_indexes {
                merge_record_fields(&mut merged[index], &record);
            }
        }
    }
    merged
}

fn sort_inventory_records(records: &mut [AccountKeyPackageRecord]) {
    records.sort_by(|left, right| {
        right
            .published_at
            .cmp(&left.published_at)
            .then_with(|| left.key_package_event_id.cmp(&right.key_package_event_id))
            .then_with(|| left.key_package_ref_hex.cmp(&right.key_package_ref_hex))
            .then_with(|| left.key_package_id.cmp(&right.key_package_id))
    });
}

pub(crate) fn owned_key_package_local_state(
    key_package_ref: &[u8],
    lifecycle: Option<&cgka_traits::KeyPackageLifecycleState>,
) -> AccountKeyPackageLocalState {
    let Some(lifecycle) = lifecycle else {
        return AccountKeyPackageLocalState::OtherOwned;
    };
    if lifecycle.current_key_package_ref.as_deref() == Some(key_package_ref) {
        return AccountKeyPackageLocalState::Current;
    }
    if lifecycle
        .pending_replacement
        .as_ref()
        .is_some_and(|pending| pending.key_package_ref == key_package_ref)
    {
        return AccountKeyPackageLocalState::PendingReplacement;
    }
    if lifecycle
        .retained_private_material
        .iter()
        .any(|retained| retained.key_package_ref == key_package_ref)
    {
        return AccountKeyPackageLocalState::RetainedPrivateMaterial;
    }
    AccountKeyPackageLocalState::OtherOwned
}

pub(crate) fn merge_key_package_inventory(
    locals: impl IntoIterator<Item = AccountKeyPackageInventoryEntry>,
    relays: impl IntoIterator<Item = AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageInventoryEntry> {
    let locals = locals.into_iter().collect::<Vec<_>>();
    let mut records = locals
        .iter()
        .map(|entry| entry.record.clone())
        .collect::<Vec<_>>();
    records.extend(relays);
    attach_local_state(merge_key_package_records(records), &locals)
}

fn attach_local_state(
    records: Vec<AccountKeyPackageRecord>,
    locals: &[AccountKeyPackageInventoryEntry],
) -> Vec<AccountKeyPackageInventoryEntry> {
    records
        .into_iter()
        .map(|record| {
            let local_state = if record.local {
                locals
                    .iter()
                    .find(|entry| {
                        entry.record.account_id_hex == record.account_id_hex
                            && !entry.record.key_package_ref_hex.is_empty()
                            && entry.record.key_package_ref_hex == record.key_package_ref_hex
                    })
                    .map(|entry| entry.local_state)
                    // Owned rows have nonempty refs preserved by the overlay,
                    // so this lookup should always hit for production inputs.
                    .unwrap_or(AccountKeyPackageLocalState::OtherOwned)
            } else {
                AccountKeyPackageLocalState::NotLocal
            };
            AccountKeyPackageInventoryEntry {
                record,
                local_state,
            }
        })
        .collect()
}

pub(crate) fn merge_key_package_records(
    mut records: Vec<AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRecord> {
    // Rank relay events by addressable slot before local overlays can raise
    // published timestamps. Matching by KeyPackageRef is deliberately not a
    // general equivalence relation: distinct slots stay separate even when they
    // advertise the same usable package.
    for record in &mut records {
        record.source_relays.sort();
        record.source_relays.dedup();
    }
    records.sort_by(record_identity_cmp);
    let locals = records
        .iter()
        .filter(|record| record.local)
        .cloned()
        .collect::<Vec<_>>();
    let mut merged =
        current_relay_key_package_records(records.into_iter().filter(|record| record.relay));
    merged = overlay_local_key_package_records(merged, locals);
    sort_inventory_records(&mut merged);
    merged
}

fn record_identity_cmp(
    left: &AccountKeyPackageRecord,
    right: &AccountKeyPackageRecord,
) -> std::cmp::Ordering {
    left.key_package_event_id
        .cmp(&right.key_package_event_id)
        .then_with(|| left.key_package_ref_hex.cmp(&right.key_package_ref_hex))
        .then_with(|| left.key_package_id.cmp(&right.key_package_id))
        .then_with(|| left.local.cmp(&right.local))
        .then_with(|| left.relay.cmp(&right.relay))
        .then_with(|| left.published_at.cmp(&right.published_at))
        .then_with(|| left.source_relays.cmp(&right.source_relays))
}

fn merge_record_fields(existing: &mut AccountKeyPackageRecord, record: &AccountKeyPackageRecord) {
    existing.local |= record.local;
    existing.relay |= record.relay;
    existing.published_at = existing.published_at.max(record.published_at);
    existing.key_package_bytes = existing.key_package_bytes.max(record.key_package_bytes);
    if existing.account_label.is_none() {
        existing.account_label.clone_from(&record.account_label);
    }
    if existing.key_package_event_id.is_empty() {
        existing
            .key_package_event_id
            .clone_from(&record.key_package_event_id);
    }
    if existing.key_package_ref_hex.is_empty() {
        existing
            .key_package_ref_hex
            .clone_from(&record.key_package_ref_hex);
    }
    push_unique_strings(&mut existing.source_relays, record.source_relays.clone());
    existing.source_relays.sort();
}

pub(crate) fn parse_key_package_event_id_hex(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    let bytes = hex::decode(trimmed)?;
    if bytes.len() != 32 {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "KeyPackage event id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(trimmed.to_owned())
}

pub(crate) fn publish_endpoints_from_bootstrap(
    bootstrap: &AccountRelayListBootstrap,
) -> Vec<TransportEndpoint> {
    if bootstrap.bootstrap_relays.is_empty() {
        bootstrap.default_relays.clone()
    } else {
        bootstrap.bootstrap_relays.clone()
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    fn record(event: &str, reference: &str, local: bool, relay: bool) -> AccountKeyPackageRecord {
        record_on_slot(
            "account",
            &format!("slot-{event}-{reference}"),
            event,
            reference,
            event.len() as u64,
            local,
            relay,
            if relay {
                vec!["wss://relay.example".to_owned()]
            } else {
                Vec::new()
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_on_slot(
        account: &str,
        slot: &str,
        event: &str,
        reference: &str,
        published_at: u64,
        local: bool,
        relay: bool,
        source_relays: Vec<String>,
    ) -> AccountKeyPackageRecord {
        AccountKeyPackageRecord {
            account_label: local.then(|| "device".to_owned()),
            account_id_hex: account.to_owned(),
            key_package_id: slot.to_owned(),
            key_package_ref_hex: reference.to_owned(),
            key_package_event_id: event.to_owned(),
            published_at,
            key_package_bytes: 123,
            source_relays,
            local,
            relay,
        }
    }

    fn event_ids(records: &[AccountKeyPackageRecord]) -> BTreeSet<&str> {
        records
            .iter()
            .map(|record| record.key_package_event_id.as_str())
            .collect()
    }

    #[test]
    fn local_and_relay_copy_merge_without_losing_distinct_relay_events() {
        let records = merge_key_package_records(vec![
            record("", "ref", true, false),
            record("event-b", "ref", false, true),
            record("event-a", "ref", false, true),
        ]);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.local && record.relay));
        assert_eq!(event_ids(&records), BTreeSet::from(["event-a", "event-b"]));
        assert_eq!(
            records
                .iter()
                .map(|record| record.key_package_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["slot-event-a-ref", "slot-event-b-ref"])
        );
    }

    #[test]
    fn same_ref_distinct_slots_remain_separate() {
        let records = merge_key_package_records(vec![
            record_on_slot(
                "account",
                "slot-a",
                "event-a",
                "shared-ref",
                10,
                false,
                true,
                vec!["wss://relay.example".to_owned()],
            ),
            record_on_slot(
                "account",
                "slot-b",
                "event-b",
                "shared-ref",
                11,
                false,
                true,
                vec!["wss://relay.example".to_owned()],
            ),
            record_on_slot(
                "account",
                "local-slot",
                "",
                "shared-ref",
                1,
                true,
                false,
                Vec::new(),
            ),
        ]);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.local && record.relay));
        assert_eq!(event_ids(&records), BTreeSet::from(["event-a", "event-b"]));
    }

    #[test]
    fn same_slot_text_for_different_authors_does_not_coalesce() {
        let records = merge_key_package_records(vec![
            record_on_slot(
                "author-a",
                "shared-slot",
                "event-a",
                "ref-a",
                10,
                false,
                true,
                vec!["wss://relay.example".to_owned()],
            ),
            record_on_slot(
                "author-b",
                "shared-slot",
                "event-b",
                "ref-b",
                11,
                false,
                true,
                vec!["wss://relay.example".to_owned()],
            ),
        ]);
        assert_eq!(records.len(), 2);
        assert_eq!(event_ids(&records), BTreeSet::from(["event-a", "event-b"]));
    }

    #[test]
    fn same_slot_newest_valid_relay_event_wins() {
        let older = record_on_slot(
            "account",
            "stable-slot",
            "event-old",
            "ref-old",
            10,
            false,
            true,
            vec!["wss://older.example".to_owned()],
        );
        let newer_same_ref = record_on_slot(
            "account",
            "stable-slot",
            "event-new",
            "ref-old",
            20,
            false,
            true,
            vec!["wss://newer.example".to_owned()],
        );
        let newer_other_ref = record_on_slot(
            "account",
            "stable-slot",
            "event-new-other",
            "ref-new",
            21,
            false,
            true,
            vec!["wss://newer-other.example".to_owned()],
        );
        for input in [
            vec![older.clone(), newer_same_ref.clone()],
            vec![newer_same_ref.clone(), older.clone()],
            vec![older.clone(), newer_other_ref.clone()],
            vec![newer_other_ref.clone(), older.clone()],
        ] {
            let expected_current = input
                .iter()
                .max_by_key(|record| record.published_at)
                .unwrap()
                .key_package_event_id
                .clone();
            let records = merge_key_package_records(input.clone());
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].key_package_event_id, expected_current);
            assert_eq!(records[0].source_relays.len(), 1);
            let history = account_key_package_relay_events_from_records(input);
            assert_eq!(history.len(), 2);
            assert_eq!(history.iter().filter(|event| event.is_current).count(), 1);
            assert_eq!(
                history
                    .iter()
                    .map(|event| event.key_package_event_id.as_str())
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from(["event-old", expected_current.as_str()])
            );
        }
    }

    #[test]
    fn same_slot_equal_timestamp_uses_lower_event_id() {
        let higher = record_on_slot(
            "account",
            "stable-slot",
            "ffff",
            "ref-high",
            42,
            false,
            true,
            vec!["wss://b.example".to_owned(), "wss://a.example".to_owned()],
        );
        let lower = record_on_slot(
            "account",
            "stable-slot",
            "0000",
            "ref-low",
            42,
            false,
            true,
            vec!["wss://c.example".to_owned()],
        );
        let newer = record_on_slot(
            "account",
            "stable-slot",
            "eeee",
            "ref-newer",
            43,
            false,
            true,
            vec!["wss://d.example".to_owned()],
        );
        for input in [
            vec![higher.clone(), lower.clone()],
            vec![lower.clone(), higher.clone()],
        ] {
            let records = merge_key_package_records(input.clone());
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].key_package_event_id, "0000");
            assert_eq!(records[0].source_relays, vec!["wss://c.example"]);
            let history = account_key_package_relay_events_from_records(input);
            assert_eq!(
                history
                    .iter()
                    .map(|event| (event.key_package_event_id.as_str(), event.is_current))
                    .collect::<Vec<_>>(),
                vec![("0000", true), ("ffff", false)]
            );
        }
        let records = merge_key_package_records(vec![newer.clone(), lower.clone()]);
        assert_eq!(records[0].key_package_event_id, "eeee");
        let history = account_key_package_relay_events_from_records(vec![newer, higher, lower]);
        assert_eq!(
            history
                .iter()
                .map(|event| event.key_package_event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["eeee", "0000", "ffff"]
        );
        assert_eq!(history[0].source_relays, vec!["wss://d.example"]);
        assert_eq!(
            history[2].source_relays,
            vec!["wss://a.example", "wss://b.example"]
        );
    }

    #[test]
    fn local_overlay_does_not_change_slot_selection() {
        let older = record_on_slot(
            "account",
            "stable-slot",
            "event-old",
            "ref-old",
            10,
            false,
            true,
            vec!["wss://older.example".to_owned()],
        );
        let newer = record_on_slot(
            "account",
            "stable-slot",
            "event-new",
            "ref-new",
            20,
            false,
            true,
            vec!["wss://newer.example".to_owned()],
        );
        let high_local_old = record_on_slot(
            "account",
            "stable-slot",
            "event-old",
            "ref-old",
            99,
            true,
            false,
            Vec::new(),
        );
        let idless_winner_ref = record_on_slot(
            "account",
            "other-slot",
            "",
            "ref-new",
            5,
            true,
            false,
            Vec::new(),
        );
        let retained_other_ref = record_on_slot(
            "account",
            "stable-slot",
            "",
            "ref-retained",
            8,
            true,
            false,
            Vec::new(),
        );
        let empty_identity_local = record_on_slot("", "", "", "", 1, true, false, Vec::new());
        let empty_identity_relay = record_on_slot(
            "",
            "",
            "",
            "",
            2,
            false,
            true,
            vec!["wss://empty.example".to_owned()],
        );
        let duplicate_newer = record_on_slot(
            "account",
            "stable-slot",
            "event-new",
            "ref-new",
            20,
            false,
            true,
            vec!["wss://newer-b.example".to_owned()],
        );

        let input = vec![
            older.clone(),
            newer.clone(),
            high_local_old.clone(),
            idless_winner_ref.clone(),
            retained_other_ref.clone(),
            empty_identity_local.clone(),
            empty_identity_relay.clone(),
            duplicate_newer.clone(),
        ];
        let expected = merge_key_package_records(input.clone());
        let reversed = merge_key_package_records(input.into_iter().rev().collect());
        assert_eq!(expected, reversed);

        let current = expected
            .iter()
            .find(|record| record.relay && record.key_package_id == "stable-slot")
            .expect("current slot winner");
        assert_eq!(current.key_package_event_id, "event-new");
        assert_eq!(current.published_at, 20);
        assert!(current.local);
        assert_eq!(
            current.source_relays,
            vec!["wss://newer-b.example", "wss://newer.example"]
        );

        let superseded_local = expected
            .iter()
            .find(|record| record.key_package_event_id == "event-old")
            .expect("superseded local event remains local-only");
        assert!(superseded_local.local);
        assert!(!superseded_local.relay);
        assert_eq!(superseded_local.published_at, 99);

        let retained = expected
            .iter()
            .find(|record| record.key_package_ref_hex == "ref-retained")
            .expect("different-ref retained bundle stays local-only");
        assert!(retained.local);
        assert!(!retained.relay);

        assert_eq!(
            expected
                .iter()
                .filter(|record| record.account_id_hex.is_empty())
                .count(),
            2
        );

        let history = account_key_package_relay_events_from_records(vec![
            older,
            newer,
            duplicate_newer,
            empty_identity_relay,
        ]);
        let current_history = history
            .iter()
            .filter(|event| event.is_current)
            .map(|event| event.key_package_event_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(current_history.contains("event-new"));
        assert!(!current_history.contains("event-old"));
        assert_eq!(
            history
                .iter()
                .find(|event| event.key_package_event_id == "event-new")
                .map(|event| event.source_relays.clone()),
            Some(vec![
                "wss://newer-b.example".to_owned(),
                "wss://newer.example".to_owned(),
            ])
        );
    }

    #[test]
    fn empty_identity_records_only_merge_by_stable_slot() {
        let records = merge_key_package_records(vec![
            record("", "", true, false),
            record("", "", false, true),
        ]);
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn relay_list_ties_choose_lexically_lower_event_id_in_any_input_order() {
        let account_id = "11".repeat(32);
        let make = |id: &str, kind: u64, relay: &str| RelayEventRecord {
            endpoints: vec![TransportEndpoint("wss://source.example".to_owned())],
            event: NostrTransportEvent {
                id: id.repeat(64),
                pubkey: account_id.clone(),
                created_at: 42,
                kind,
                tags: vec![if kind == KIND_NIP65_RELAY_LIST {
                    vec!["r".to_owned(), relay.to_owned(), "write".to_owned()]
                } else {
                    vec!["relay".to_owned(), relay.to_owned()]
                }],
                content: String::new(),
                sig: None,
            },
        };
        let lower_nip65 = make("0", KIND_NIP65_RELAY_LIST, "wss://lower-outbox.example");
        let higher_nip65 = make("f", KIND_NIP65_RELAY_LIST, "wss://higher-outbox.example");
        let lower_inbox = make(
            "0",
            KIND_MARMOT_INBOX_RELAY_LIST,
            "wss://lower-inbox.example",
        );
        let higher_inbox = make(
            "f",
            KIND_MARMOT_INBOX_RELAY_LIST,
            "wss://higher-inbox.example",
        );
        let input = vec![higher_inbox, lower_nip65, higher_nip65, lower_inbox];
        for records in [input.clone(), input.into_iter().rev().collect()] {
            let status = relay_list_status_from_records(&account_id, records);
            assert_eq!(status.nip65.relays, vec!["wss://lower-outbox.example"]);
            assert_eq!(status.inbox.relays, vec!["wss://lower-inbox.example"]);
        }
    }

    #[test]
    fn merge_is_independent_of_input_order() {
        let input = vec![
            record("", "ref", true, false),
            record("event-b", "ref", false, true),
            record("event-a", "ref", false, true),
        ];
        let expected = merge_key_package_records(input.clone());
        let actual = merge_key_package_records(input.into_iter().rev().collect());
        assert_eq!(actual, expected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{
        KeyPackageLifecycleState, PendingKeyPackageReplacement, RetainedKeyPackagePrivateMaterial,
        Timestamp,
    };

    fn entry(
        event: &str,
        reference: &str,
        local: bool,
        relay: bool,
        local_state: AccountKeyPackageLocalState,
    ) -> AccountKeyPackageInventoryEntry {
        AccountKeyPackageInventoryEntry {
            record: record(event, reference, local, relay),
            local_state,
        }
    }

    fn record(event: &str, reference: &str, local: bool, relay: bool) -> AccountKeyPackageRecord {
        AccountKeyPackageRecord {
            account_label: local.then(|| "device".to_owned()),
            account_id_hex: "account".to_owned(),
            key_package_id: format!("slot-{event}-{reference}"),
            key_package_ref_hex: reference.to_owned(),
            key_package_event_id: event.to_owned(),
            published_at: event.len() as u64,
            key_package_bytes: 123,
            source_relays: if relay {
                vec!["wss://relay.example".to_owned()]
            } else {
                Vec::new()
            },
            local,
            relay,
        }
    }

    #[test]
    fn owned_lifecycle_refs_map_to_exact_local_states() {
        let current = vec![1_u8, 2, 3];
        let pending = vec![4_u8, 5, 6];
        let retained = vec![7_u8, 8, 9];
        let other = vec![10_u8, 11, 12];
        let mut lifecycle = KeyPackageLifecycleState::slot_only("stable-slot".into());
        lifecycle.current_key_package_ref = Some(current.clone());
        lifecycle.pending_replacement = Some(PendingKeyPackageReplacement {
            generation_revision: 1,
            key_package: KeyPackage::new(vec![0]),
            key_package_ref: pending.clone(),
            authored_created_at: Timestamp(1),
            not_before: Timestamp(1),
            not_after: Timestamp(2),
            refresh_at: Timestamp(2),
            signed_event: None,
            targets: Vec::new(),
            attempt_count: 0,
            last_failure_code: None,
            consumed_at: None,
        });
        lifecycle.retained_private_material = vec![RetainedKeyPackagePrivateMaterial {
            key_package: KeyPackage::new(vec![1]),
            key_package_ref: retained.clone(),
            not_after: Timestamp(2),
            replaced_at: Timestamp(1),
            consumed: false,
        }];

        assert_eq!(
            owned_key_package_local_state(&current, Some(&lifecycle)),
            AccountKeyPackageLocalState::Current
        );
        assert_eq!(
            owned_key_package_local_state(&pending, Some(&lifecycle)),
            AccountKeyPackageLocalState::PendingReplacement
        );
        assert_eq!(
            owned_key_package_local_state(&retained, Some(&lifecycle)),
            AccountKeyPackageLocalState::RetainedPrivateMaterial
        );
        assert_eq!(
            owned_key_package_local_state(&other, Some(&lifecycle)),
            AccountKeyPackageLocalState::OtherOwned
        );
        assert_eq!(
            owned_key_package_local_state(&current, None),
            AccountKeyPackageLocalState::OtherOwned
        );
    }

    #[test]
    fn typed_merge_keeps_current_echo_retained_and_relay_only_states() {
        let locals = vec![
            entry(
                "event-current",
                "ref-current",
                true,
                false,
                AccountKeyPackageLocalState::Current,
            ),
            entry(
                "",
                "ref-retained",
                true,
                false,
                AccountKeyPackageLocalState::RetainedPrivateMaterial,
            ),
            entry(
                "",
                "ref-other",
                true,
                false,
                AccountKeyPackageLocalState::OtherOwned,
            ),
        ];
        let relays = vec![
            record("event-current", "ref-current", false, true),
            record("event-foreign", "ref-foreign", false, true),
        ];
        let merged = merge_key_package_inventory(locals, relays);
        let by_ref = merged
            .iter()
            .map(|entry| {
                (
                    entry.record.key_package_ref_hex.as_str(),
                    entry.local_state,
                    entry.record.local,
                    entry.record.relay,
                )
            })
            .collect::<Vec<_>>();
        assert!(by_ref.contains(&(
            "ref-current",
            AccountKeyPackageLocalState::Current,
            true,
            true
        )));
        assert!(by_ref.contains(&(
            "ref-retained",
            AccountKeyPackageLocalState::RetainedPrivateMaterial,
            true,
            false
        )));
        assert!(by_ref.contains(&(
            "ref-other",
            AccountKeyPackageLocalState::OtherOwned,
            true,
            false
        )));
        assert!(by_ref.contains(&(
            "ref-foreign",
            AccountKeyPackageLocalState::NotLocal,
            false,
            true
        )));
        assert!(!merged.iter().any(|entry| entry.local_state
            == AccountKeyPackageLocalState::NotLocal
            && entry.record.local));
        assert!(!merged.iter().any(|entry| {
            entry.local_state == AccountKeyPackageLocalState::RetainedPrivateMaterial
                && entry.record.relay
        }));
    }

    #[test]
    fn observed_retained_material_keeps_retained_state_and_relay_fact() {
        let locals = vec![entry(
            "",
            "ref-retained",
            true,
            false,
            AccountKeyPackageLocalState::RetainedPrivateMaterial,
        )];
        let relays = vec![record("event-retained", "ref-retained", false, true)];
        let merged = merge_key_package_inventory(locals, relays);
        let retained = merged
            .iter()
            .find(|entry| entry.record.key_package_ref_hex == "ref-retained")
            .expect("retained row remains");
        assert_eq!(
            retained.local_state,
            AccountKeyPackageLocalState::RetainedPrivateMaterial
        );
        assert!(retained.record.local);
        assert!(retained.record.relay);
        assert_eq!(retained.record.key_package_event_id, "event-retained");
    }

    #[test]
    fn unsigned_pending_stays_pending_and_does_not_claim_publication() {
        let pending = entry(
            "",
            "ref-pending",
            true,
            false,
            AccountKeyPackageLocalState::PendingReplacement,
        );
        let merged = merge_key_package_inventory(vec![pending], Vec::new());
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].local_state,
            AccountKeyPackageLocalState::PendingReplacement
        );
        assert!(merged[0].record.local);
        assert!(!merged[0].record.relay);
        assert!(merged[0].record.key_package_event_id.is_empty());
    }
}
