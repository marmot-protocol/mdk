//! Stateless parsing and validation for relay-fetched account relay lists and
//! Marmot KeyPackages.
//!
//! These helpers turn directory relay-event records into typed relay-list
//! status and [`FetchedKeyPackage`] values, validate KeyPackage event tags and
//! decoded metadata, reconcile fresh vs cached results, merge KeyPackage
//! records, and pick publish endpoints. They hold no `MarmotApp` state.

use std::collections::BTreeMap;

use cgka_engine::account_identity_proof::ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE;
use cgka_engine::key_package::key_package_metadata;
use cgka_traits::engine::KeyPackage;
use cgka_traits::{MessageId, TransportEndpoint};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::error::AppError;
use crate::relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};
use crate::{
    AccountKeyPackageRecord, AccountRelayListBootstrap, AccountRelayListStatus, DirectoryFreshness,
    DirectoryKeyPackage, DirectorySelection, FetchedKeyPackage, UserDirectoryRecord,
    push_unique_strings, relays_from_relay_list_event, sort_directory_records,
};

pub(crate) fn relay_list_status_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
) -> AccountRelayListStatus {
    sort_directory_records(&mut records);
    let mut status = AccountRelayListStatus::empty();
    for record in records {
        if record.event.pubkey != account_id_hex {
            continue;
        }
        let relays = relays_from_relay_list_event(&record.event);
        if relays.is_empty() {
            continue;
        }
        match record.event.kind {
            KIND_NIP65_RELAY_LIST => status.nip65.relays = relays,
            KIND_MARMOT_INBOX_RELAY_LIST => status.inbox.relays = relays,
            _ => continue,
        }
        push_unique_strings(
            &mut status.bootstrap_relays,
            record
                .endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect::<Vec<_>>(),
        );
    }
    status.refresh();
    status
}

pub(crate) fn fresh_relay_list_status_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> DirectorySelection<AccountRelayListStatus> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.pubkey != account_id_hex
            || !matches!(
                record.event.kind,
                KIND_NIP65_RELAY_LIST | KIND_MARMOT_INBOX_RELAY_LIST
            )
        {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    DirectorySelection {
        value: relay_list_status_from_records(account_id_hex, records),
        rejected_future,
    }
}

pub(crate) fn relay_list_queries(account_id_hex: String) -> Vec<DirectoryEventQuery> {
    [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
        .into_iter()
        .map(|kind| DirectoryEventQuery::new(kind, vec![account_id_hex.clone()], 12))
        .collect()
}

fn latest_key_package_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
) -> Result<FetchedKeyPackage, AppError> {
    sort_directory_records(&mut records);
    let mut latest = None;
    for record in records {
        if record.event.kind != KIND_MARMOT_KEY_PACKAGE || record.event.pubkey != account_id_hex {
            continue;
        }
        latest = Some(key_package_from_record(record)?);
    }
    latest.ok_or_else(|| AppError::MissingKeyPackage(account_id_hex.to_owned()))
}

pub(crate) fn latest_fresh_key_package_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> Result<DirectorySelection<Option<FetchedKeyPackage>>, AppError> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.kind != KIND_MARMOT_KEY_PACKAGE || record.event.pubkey != account_id_hex {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    match latest_key_package_from_records(account_id_hex, records) {
        Ok(value) => Ok(DirectorySelection {
            value: Some(value),
            rejected_future,
        }),
        Err(AppError::MissingKeyPackage(_)) => Ok(DirectorySelection {
            value: None,
            rejected_future,
        }),
        Err(err) => Err(err),
    }
}

fn cached_key_package_from_entry(
    entry: UserDirectoryRecord,
) -> Result<Option<FetchedKeyPackage>, AppError> {
    let Some(key_package) = entry.key_package else {
        return Ok(None);
    };
    let (decoded, key_package_ref_hex) =
        validated_cached_key_package_with_ref(&entry.account_id_hex, &key_package)?;
    Ok(Some(FetchedKeyPackage {
        account_id_hex: entry.account_id_hex,
        key_package: decoded,
        key_package_id: key_package.key_package_id,
        key_package_ref_hex,
        key_package_event_id: key_package.key_package_event_id,
        created_at: key_package.created_at,
        source_relays: key_package.source_relays,
        relay_lists: entry.relay_lists,
    }))
}

pub(crate) fn validated_cached_key_package(
    account_id_hex: &str,
    key_package: &DirectoryKeyPackage,
) -> Result<KeyPackage, AppError> {
    validated_cached_key_package_with_ref(account_id_hex, key_package)
        .map(|(key_package, _)| key_package)
}

fn validated_cached_key_package_with_ref(
    account_id_hex: &str,
    key_package: &DirectoryKeyPackage,
) -> Result<(KeyPackage, String), AppError> {
    let decoded = key_package_from_hex_with_optional_source(
        &key_package.key_package_hex,
        &key_package.key_package_event_id,
    )?;
    let metadata = key_package_metadata(&decoded)
        .map_err(|e| AppError::InvalidKeyPackageEvent(e.to_string()))?;
    if metadata.credential_identity_hex != account_id_hex {
        return Err(AppError::InvalidKeyPackageEvent(
            "cached KeyPackage credential identity does not match directory account".into(),
        ));
    }
    if !key_package.key_package_ref_hex.is_empty()
        && key_package.key_package_ref_hex != metadata.key_package_ref_hex
    {
        return Err(AppError::InvalidKeyPackageEvent(
            "cached KeyPackage ref does not match decoded KeyPackageRef".into(),
        ));
    }
    Ok((decoded, metadata.key_package_ref_hex))
}

pub(crate) fn key_package_from_hex_with_optional_source(
    key_package_hex: &str,
    event_id_hex: &str,
) -> Result<KeyPackage, AppError> {
    let bytes = hex::decode(key_package_hex)?;
    if event_id_hex.is_empty() {
        return Ok(KeyPackage::new(bytes));
    }
    Ok(KeyPackage::with_source_event_id(
        bytes,
        key_package_event_id_from_hex(event_id_hex)?,
    ))
}

fn key_package_event_id_from_hex(event_id_hex: &str) -> Result<MessageId, AppError> {
    let bytes = hex::decode(event_id_hex)?;
    if bytes.len() != 32 {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "KeyPackage event id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(MessageId::new(bytes))
}

pub(crate) fn relay_lists_have_any_relays(status: &AccountRelayListStatus) -> bool {
    !status.nip65.relays.is_empty() || !status.inbox.relays.is_empty()
}

pub(crate) fn fill_missing_relay_lists_from_cached(
    status: &mut AccountRelayListStatus,
    cached: &AccountRelayListStatus,
) {
    if status.nip65.relays.is_empty() {
        status.nip65.relays = cached.nip65.relays.clone();
    }
    if status.inbox.relays.is_empty() {
        status.inbox.relays = cached.inbox.relays.clone();
    }
    if status.bootstrap_relays.is_empty() {
        status.bootstrap_relays = cached.bootstrap_relays.clone();
    }
    status.refresh();
}

pub(crate) fn fresh_or_cached_key_package(
    account_id_hex: &str,
    selection: DirectorySelection<Option<FetchedKeyPackage>>,
    cached_entry: Option<UserDirectoryRecord>,
) -> Result<FetchedKeyPackage, AppError> {
    if let Some(fetched) = selection.value {
        return Ok(fetched);
    }
    if selection.rejected_future
        && let Some(cached) = cached_entry
            .map(cached_key_package_from_entry)
            .transpose()?
            .flatten()
    {
        return Ok(cached);
    }
    Err(AppError::MissingKeyPackage(account_id_hex.to_owned()))
}

pub(crate) fn key_package_from_record(
    record: RelayEventRecord,
) -> Result<FetchedKeyPackage, AppError> {
    let event = record.event;
    require_key_package_tag(&event, "mls_protocol_version", |value| value == "1.0")?;
    let key_package_id = event
        .tag_value("d")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::InvalidKeyPackageEvent("missing d tag".into()))?
        .to_owned();
    let key_package_ref = event
        .tag_value("i")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::InvalidKeyPackageEvent("missing i tag".into()))?
        .to_owned();
    require_key_package_tag(&event, "mls_ciphersuite", |value| !value.is_empty())?;
    require_multi_value_key_package_tag(&event, "mls_extensions")?;
    require_multi_value_key_package_tag_contains(
        &event,
        "mls_extensions",
        &format!("0x{ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE:04x}"),
    )?;
    require_multi_value_key_package_tag(&event, "mls_proposals")?;
    require_multi_value_key_package_tag(&event, "app_components")?;
    let key_package_bytes = BASE64_STANDARD
        .decode(event.content.as_bytes())
        .map_err(|e| AppError::InvalidKeyPackageEvent(format!("invalid base64 content: {e}")))?;
    if key_package_bytes.is_empty() {
        return Err(AppError::InvalidKeyPackageEvent(
            "empty key package content".into(),
        ));
    }
    let key_package = KeyPackage::with_source_event_id(
        key_package_bytes,
        key_package_event_id_from_hex(&event.id)?,
    );
    let metadata = key_package_metadata(&key_package)
        .map_err(|e| AppError::InvalidKeyPackageEvent(e.to_string()))?;
    if metadata.credential_identity_hex != event.pubkey {
        return Err(AppError::InvalidKeyPackageEvent(
            "transport author does not match KeyPackage credential identity".into(),
        ));
    }
    if metadata.key_package_ref_hex != key_package_ref {
        return Err(AppError::InvalidKeyPackageEvent(
            "i tag does not match decoded KeyPackageRef".into(),
        ));
    }
    let mut source_relays = Vec::new();
    push_unique_strings(
        &mut source_relays,
        record
            .endpoints
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect::<Vec<_>>(),
    );
    Ok(FetchedKeyPackage {
        account_id_hex: event.pubkey,
        key_package,
        key_package_id,
        key_package_ref_hex: metadata.key_package_ref_hex,
        key_package_event_id: event.id,
        created_at: event.created_at,
        source_relays,
        relay_lists: AccountRelayListStatus::empty(),
    })
}

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

pub(crate) fn merge_key_package_records(
    records: Vec<AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRecord> {
    let mut merged: BTreeMap<String, AccountKeyPackageRecord> = BTreeMap::new();
    for record in records {
        let key = if !record.key_package_event_id.is_empty() {
            record.key_package_event_id.clone()
        } else if !record.key_package_ref_hex.is_empty() {
            record.key_package_ref_hex.clone()
        } else {
            record.key_package_id.clone()
        };
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.local |= record.local;
                existing.relay |= record.relay;
                existing.published_at = existing.published_at.max(record.published_at);
                if existing.account_label.is_none() {
                    existing.account_label = record.account_label.clone();
                }
                push_unique_strings(&mut existing.source_relays, record.source_relays.clone());
            })
            .or_insert(record);
    }
    let mut records = merged.into_values().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        right
            .published_at
            .cmp(&left.published_at)
            .then_with(|| left.key_package_event_id.cmp(&right.key_package_event_id))
    });
    records
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

/// Per spec/transports/nostr.md, each KeyPackage id-list tag is exactly one
/// tag. A consumer MUST reject an event that repeats an id-list tag name rather
/// than silently reading the first occurrence (two consumers could otherwise
/// pick different occurrences and disagree on advertised capabilities).
fn reject_duplicate_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
) -> Result<(), AppError> {
    let count = event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .count();
    if count > 1 {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "duplicate {name} tag"
        )));
    }
    Ok(())
}

pub(crate) fn require_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
) -> Result<(), AppError> {
    reject_duplicate_key_package_tag(event, name)?;
    match event.tag_value(name) {
        Some(value) if predicate(value) => Ok(()),
        Some(value) => Err(AppError::InvalidKeyPackageEvent(format!(
            "invalid {name} tag: {value}"
        ))),
        None => Err(AppError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        ))),
    }
}

pub(crate) fn require_multi_value_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
) -> Result<(), AppError> {
    reject_duplicate_key_package_tag(event, name)?;
    let Some(tag) = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
    else {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        )));
    };
    if tag.iter().skip(1).any(|value| !value.trim().is_empty()) {
        Ok(())
    } else {
        Err(AppError::InvalidKeyPackageEvent(format!(
            "empty {name} tag"
        )))
    }
}

pub(crate) fn require_multi_value_key_package_tag_contains(
    event: &NostrTransportEvent,
    name: &str,
    required: &str,
) -> Result<(), AppError> {
    reject_duplicate_key_package_tag(event, name)?;
    let Some(tag) = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
    else {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        )));
    };
    if tag
        .iter()
        .skip(1)
        .any(|value| value.eq_ignore_ascii_case(required))
    {
        Ok(())
    } else {
        Err(AppError::InvalidKeyPackageEvent(format!(
            "{name} tag missing required value {required}"
        )))
    }
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
