//! User-directory record types and stateless directory-record helpers.
//!
//! Holds the public `UserDirectory*` DTOs surfaced to `marmot-uniffi`/`cli`,
//! plus conversions between cached [`UserDirectoryRecord`]s and shared
//! [`PublicDirectoryUserRecord`]s, recency selection, Nostr profile/follow-list
//! parsing, and search-match ranking. These complement the stateful directory
//! cache/sync modules in `directory/`; they hold no `MarmotApp` state and
//! operate purely on records.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use storage_sqlite::PublicDirectoryUserRecord;

use crate::error::AppError;
use crate::ids::parse_account_id_hex;
use crate::relay_plane::DirectoryRelayEventRecord as RelayEventRecord;
use crate::{
    AccountRelayListStatus, DirectoryFreshness, DirectorySelection, KIND_NOSTR_CONTACT_LIST,
    KIND_NOSTR_METADATA, sort_directory_records,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectoryRecord {
    pub account_id_hex: String,
    pub npub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_account: Option<UserDirectoryLocalAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<UserProfileMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub follows: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub follow_source_relays: Vec<String>,
    pub relay_lists: AccountRelayListStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package: Option<DirectoryKeyPackage>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectoryLocalAccount {
    pub label: String,
    pub local_signing: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_relays: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectoryRefresh {
    pub account_id_hex: String,
    pub follow_count: usize,
    pub profile_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectorySearch {
    pub searcher_account_id_hex: String,
    pub query: String,
    pub radius_start: u8,
    pub radius_end: u8,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectorySearchResult {
    pub account_id_hex: String,
    pub npub: String,
    pub radius: u8,
    pub matched_field: String,
    pub match_quality: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<UserProfileMetadata>,
}

impl UserDirectorySearch {
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        if self.radius_start > self.radius_end {
            return Err(AppError::InvalidDirectorySearch(
                "radius_start must be less than or equal to radius_end".into(),
            ));
        }
        parse_account_id_hex(&self.searcher_account_id_hex)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryKeyPackage {
    pub key_package_id: String,
    #[serde(default)]
    pub key_package_ref_hex: String,
    #[serde(default)]
    pub key_package_event_id: String,
    pub key_package_hex: String,
    pub created_at: u64,
    pub source_relays: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FetchedFollowList {
    pub(crate) follows: Vec<String>,
    pub(crate) source_relays: Vec<String>,
}

pub(crate) fn public_directory_user_record(
    entry: &UserDirectoryRecord,
) -> Result<PublicDirectoryUserRecord, AppError> {
    let mut relay_lists = entry.relay_lists.clone();
    relay_lists.bootstrap_relays.clear();

    let profile_json = entry
        .profile
        .clone()
        .map(|mut profile| {
            profile.source_relays.clear();
            serde_json::to_string(&profile)
        })
        .transpose()?;
    let key_package_json = entry
        .key_package
        .clone()
        .map(|mut key_package| {
            key_package.source_relays.clear();
            serde_json::to_string(&key_package)
        })
        .transpose()?;

    Ok(PublicDirectoryUserRecord {
        account_id_hex: entry.account_id_hex.clone(),
        npub: entry.npub.clone(),
        profile_json,
        relay_lists_json: serde_json::to_string(&relay_lists)?,
        key_package_json,
        event_id_hex: entry.key_package.as_ref().and_then(|key_package| {
            (!key_package.key_package_event_id.is_empty())
                .then_some(key_package.key_package_event_id.clone())
        }),
        event_kind: None,
        event_created_at: entry
            .profile
            .as_ref()
            .map(|profile| profile.created_at)
            .or_else(|| {
                entry
                    .key_package
                    .as_ref()
                    .map(|key_package| key_package.created_at)
            }),
        follows: entry.follows.clone(),
    })
}

pub(crate) fn user_directory_record_from_public(
    record: PublicDirectoryUserRecord,
) -> Result<UserDirectoryRecord, AppError> {
    Ok(UserDirectoryRecord {
        account_id_hex: record.account_id_hex,
        npub: record.npub,
        local_account: None,
        profile: record
            .profile_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
        follows: record.follows,
        follow_source_relays: Vec::new(),
        relay_lists: serde_json::from_str(&record.relay_lists_json)?,
        key_package: record
            .key_package_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
    })
}

fn directory_record_recency(entry: &UserDirectoryRecord) -> u64 {
    entry
        .profile
        .as_ref()
        .map(|profile| profile.created_at)
        .into_iter()
        .chain(
            entry
                .key_package
                .as_ref()
                .map(|key_package| key_package.created_at),
        )
        .max()
        .unwrap_or_default()
}

pub(crate) fn select_newer_directory_entry(
    cached: Option<UserDirectoryRecord>,
    shared: Option<UserDirectoryRecord>,
) -> Option<UserDirectoryRecord> {
    match (cached, shared) {
        (Some(cached), Some(shared)) => {
            if directory_record_recency(&shared) > directory_record_recency(&cached) {
                Some(shared)
            } else {
                Some(cached)
            }
        }
        (Some(entry), None) | (None, Some(entry)) => Some(entry),
        (None, None) => None,
    }
}

pub(crate) fn upsert_newer_directory_entry(
    entries_by_id: &mut BTreeMap<String, UserDirectoryRecord>,
    entry: UserDirectoryRecord,
) {
    match entries_by_id.entry(entry.account_id_hex.clone()) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(entry);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            if directory_record_recency(&entry) > directory_record_recency(slot.get()) {
                *slot.get_mut() = entry;
            }
        }
    }
}

pub(crate) fn profile_from_record(
    record: RelayEventRecord,
) -> Option<(String, UserProfileMetadata)> {
    let content = serde_json::from_str::<serde_json::Value>(&record.event.content).ok()?;
    Some((
        record.event.pubkey.clone(),
        UserProfileMetadata {
            name: string_field(&content, "name"),
            display_name: string_field(&content, "display_name")
                .or_else(|| string_field(&content, "displayName")),
            about: string_field(&content, "about"),
            picture: string_field(&content, "picture"),
            nip05: string_field(&content, "nip05"),
            lud16: string_field(&content, "lud16"),
            created_at: record.event.created_at,
            source_relays: source_relays_from_record(&record),
        },
    ))
}

/// Defensive cap on any single ingested profile field. Nostr kind:0 content
/// is attacker-controlled (anyone can publish any metadata to a relay), so we
/// bound each field to keep a malicious multi-megabyte value from bloating the
/// directory cache and downstream consumers. 4096 chars is generous for any
/// legitimate name/about/url. Char-based (not byte) truncation keeps the
/// result valid UTF-8.
const MAX_PROFILE_FIELD_CHARS: usize = 4096;

fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_PROFILE_FIELD_CHARS).collect())
}

pub(crate) fn source_relays_from_record(record: &RelayEventRecord) -> Vec<String> {
    let mut relays = record
        .endpoints
        .iter()
        .map(|endpoint| endpoint.0.clone())
        .collect::<Vec<_>>();
    relays.sort();
    relays.dedup();
    relays
}

#[derive(Clone, Debug)]
pub(crate) struct UserRecordMatch {
    pub(crate) field: String,
    pub(crate) quality: String,
}

pub(crate) fn user_record_match(
    record: &UserDirectoryRecord,
    query: &str,
) -> Option<UserRecordMatch> {
    let mut candidates = vec![
        ("npub", record.npub.as_str()),
        ("pubkey", record.account_id_hex.as_str()),
    ];
    if let Some(profile) = &record.profile {
        if let Some(name) = profile.name.as_deref() {
            candidates.push(("name", name));
        }
        if let Some(nip05) = profile.nip05.as_deref() {
            candidates.push(("nip05", nip05));
        }
        if let Some(display_name) = profile.display_name.as_deref() {
            candidates.push(("display_name", display_name));
        }
        if let Some(about) = profile.about.as_deref() {
            candidates.push(("about", about));
        }
    }

    candidates
        .into_iter()
        .filter_map(|(field, value)| {
            let value = value.to_lowercase();
            let quality = if value == query {
                "exact"
            } else if value.starts_with(query) {
                "prefix"
            } else if value.contains(query) {
                "contains"
            } else {
                return None;
            };
            Some(UserRecordMatch {
                field: field.to_owned(),
                quality: quality.to_owned(),
            })
        })
        .min_by(|a, b| {
            match_quality_rank(&a.quality)
                .cmp(&match_quality_rank(&b.quality))
                .then_with(|| field_rank(&a.field).cmp(&field_rank(&b.field)))
        })
}

pub(crate) fn match_quality_rank(quality: &str) -> u8 {
    match quality {
        "exact" => 0,
        "prefix" => 1,
        "contains" => 2,
        _ => 3,
    }
}

pub(crate) fn field_rank(field: &str) -> u8 {
    match field {
        "name" => 0,
        "nip05" => 1,
        "display_name" => 2,
        "about" => 3,
        "npub" => 4,
        "pubkey" => 5,
        _ => 6,
    }
}

pub(crate) fn profile_content_json(profile: &UserProfileMetadata) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    if let Some(name) = profile.name.as_ref().filter(|value| !value.is_empty()) {
        value.insert("name".to_owned(), serde_json::Value::String(name.clone()));
    }
    if let Some(display_name) = profile
        .display_name
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        value.insert(
            "display_name".to_owned(),
            serde_json::Value::String(display_name.clone()),
        );
    }
    if let Some(about) = profile.about.as_ref().filter(|value| !value.is_empty()) {
        value.insert("about".to_owned(), serde_json::Value::String(about.clone()));
    }
    if let Some(picture) = profile.picture.as_ref().filter(|value| !value.is_empty()) {
        value.insert(
            "picture".to_owned(),
            serde_json::Value::String(picture.clone()),
        );
    }
    if let Some(nip05) = profile.nip05.as_ref().filter(|value| !value.is_empty()) {
        value.insert("nip05".to_owned(), serde_json::Value::String(nip05.clone()));
    }
    if let Some(lud16) = profile.lud16.as_ref().filter(|value| !value.is_empty()) {
        value.insert("lud16".to_owned(), serde_json::Value::String(lud16.clone()));
    }
    serde_json::Value::Object(value)
}

pub(crate) fn latest_follow_list_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> DirectorySelection<Option<FetchedFollowList>> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.kind != KIND_NOSTR_CONTACT_LIST || record.event.pubkey != account_id_hex {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    sort_directory_records(&mut records);
    let value = records.into_iter().rev().find_map(|record| {
        if record.event.kind == KIND_NOSTR_CONTACT_LIST && record.event.pubkey == account_id_hex {
            Some(follow_list_from_record(record))
        } else {
            None
        }
    });
    DirectorySelection {
        value,
        rejected_future,
    }
}

/// Defensive cap on accepted `p` tags per ingested contact list. Nostr kind-3
/// events are attacker-controlled (anyone can publish a list with arbitrarily
/// many follows to a relay), so we bound the follows stored from any single
/// list to keep a malicious mega-list from bloating the directory/search cache.
/// This is generous for legitimate follow lists while capping the worst case.
pub(crate) const MAX_FOLLOW_LIST_ENTRIES: usize = 2048;

pub(crate) fn follow_list_from_record(record: RelayEventRecord) -> FetchedFollowList {
    let mut follows = BTreeSet::new();
    for tag in &record.event.tags {
        if follows.len() >= MAX_FOLLOW_LIST_ENTRIES {
            break;
        }
        if tag.first().is_none_or(|name| name != "p") {
            continue;
        }
        let Some(value) = tag.get(1) else {
            continue;
        };
        if let Ok(account_id) = parse_account_id_hex(value) {
            follows.insert(account_id);
        }
    }
    FetchedFollowList {
        follows: follows.into_iter().collect(),
        source_relays: source_relays_from_record(&record),
    }
}

pub(crate) fn latest_profiles_from_records(
    mut records: Vec<RelayEventRecord>,
) -> HashMap<String, UserProfileMetadata> {
    sort_directory_records(&mut records);
    let mut profiles = HashMap::new();
    for record in records {
        if record.event.kind == KIND_NOSTR_METADATA
            && let Some(profile) = profile_from_record(record)
        {
            profiles.insert(profile.0, profile.1);
        }
    }
    profiles
}

pub(crate) fn latest_fresh_profiles_from_records(
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> DirectorySelection<HashMap<String, UserProfileMetadata>> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.kind != KIND_NOSTR_METADATA {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    DirectorySelection {
        value: latest_profiles_from_records(records),
        rejected_future,
    }
}
