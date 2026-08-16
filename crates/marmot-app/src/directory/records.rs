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
    pub banner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_relays: Vec<String>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Maximum number of account IDs accepted by one cached-identity page read.
///
/// Hosts hydrating profile caches should page larger sets. The bound keeps a
/// single local cache read from monopolizing directory-handle acquisition.
pub const MAX_CACHED_IDENTITY_PAGE_SIZE: usize = 100;

/// One row of a bounded local cached-identity page.
///
/// This is a cache read, not a network refresh. [`Self::profile`] is the only
/// signal that remotely cached kind:0 metadata is available; [`Self::resolved_name`]
/// may come from a local account label and must not be treated as remote
/// identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedIdentityProjection {
    /// Original requested identifier, preserving host input order.
    pub requested_id: String,
    /// Canonical hex account id when `requested_id` is a valid public key.
    pub account_id_hex: Option<String>,
    /// Cached kind:0 profile when the directory has one.
    pub profile: Option<UserProfileMetadata>,
    /// Local account label when this id is one of our own accounts.
    pub local_label: Option<String>,
    /// Best display string: profile `display_name`/`name`, else local label.
    pub resolved_name: Option<String>,
}

pub(crate) fn display_name_for_profile(profile: Option<&UserProfileMetadata>) -> Option<String> {
    let profile = profile?;
    profile
        .display_name
        .as_deref()
        .or(profile.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) fn cached_identity_projection(
    requested_id: String,
    account_id_hex: Option<String>,
    profile: Option<UserProfileMetadata>,
    local_label: Option<String>,
) -> CachedIdentityProjection {
    let resolved_name = display_name_for_profile(profile.as_ref()).or_else(|| local_label.clone());
    CachedIdentityProjection {
        requested_id,
        account_id_hex,
        profile,
        local_label,
        resolved_name,
    }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserDirectorySearchResult {
    pub account_id_hex: String,
    pub npub: String,
    pub radius: u8,
    pub matched_field: MatchedField,
    pub match_quality: MatchQuality,
    /// Rank assigned by an off-graph discovery provider. `None` for results
    /// found only through the local social graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_rank: Option<f64>,
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
    content.as_object()?;
    Some((
        record.event.pubkey.clone(),
        UserProfileMetadata {
            name: string_field(&content, "name"),
            display_name: string_field(&content, "display_name")
                .or_else(|| string_field(&content, "displayName")),
            about: string_field(&content, "about"),
            picture: string_field(&content, "picture"),
            banner: string_field(&content, "banner"),
            nip05: string_field(&content, "nip05"),
            lud16: string_field(&content, "lud16"),
            created_at: record.event.created_at,
            source_relays: source_relays_from_record(&record),
            extra: extra_profile_fields(&content),
        },
    ))
}

fn extra_profile_fields(content: &serde_json::Value) -> BTreeMap<String, serde_json::Value> {
    let Some(object) = content.as_object() else {
        return BTreeMap::new();
    };
    object
        .iter()
        .filter(|(key, _)| !is_known_profile_field(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn is_known_profile_field(field: &str) -> bool {
    matches!(
        field,
        "name"
            | "display_name"
            | "displayName"
            | "about"
            | "picture"
            | "banner"
            | "nip05"
            | "lud16"
            | "created_at"
            | "source_relays"
    )
}

/// Defensive cap on any single ingested profile field. Nostr kind:0 content
/// is attacker-controlled (anyone can publish any metadata to a relay), so we
/// bound each field to keep a malicious multi-megabyte value from bloating the
/// directory cache and downstream consumers. 4096 chars is generous for any
/// legitimate name/about/url. Char-based (not byte) truncation keeps the
/// result valid UTF-8.
const MAX_PROFILE_FIELD_CHARS: usize = 4096;

fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    let value = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)?;
    let value = value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_PROFILE_FIELD_CHARS)
        .collect::<String>();
    (!value.is_empty()).then_some(value)
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

/// How closely a record's field matched the query, best first.
///
/// The declaration order *is* the ranking order — [`Ord`] is derived, so a
/// new variant slots into the ranking by where it is written.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MatchQuality {
    /// The whole field equals the query.
    Exact,
    /// The field starts with the query.
    Prefix,
    /// The query appears somewhere in the field.
    Contains,
}

/// Which field of a record the query matched, most identifying first.
///
/// The declaration order *is* the ranking order (see [`MatchQuality`]): a
/// name match outranks an `about` match of the same quality, and the two
/// pubkey spellings rank last because matching them is incidental rather
/// than a search for a person by that name.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MatchedField {
    Name,
    Nip05,
    DisplayName,
    About,
    Npub,
    Pubkey,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UserRecordMatch {
    pub(crate) field: MatchedField,
    pub(crate) quality: MatchQuality,
}

impl UserRecordMatch {
    /// Ranking key: quality first, then which field matched. Sorting by this
    /// orders best match first.
    pub(crate) fn rank(&self) -> (MatchQuality, MatchedField) {
        (self.quality, self.field)
    }
}

pub(crate) fn user_record_match(
    record: &UserDirectoryRecord,
    query: &str,
) -> Option<UserRecordMatch> {
    let mut candidates = vec![
        (MatchedField::Npub, record.npub.as_str()),
        (MatchedField::Pubkey, record.account_id_hex.as_str()),
    ];
    if let Some(profile) = &record.profile {
        if let Some(name) = profile.name.as_deref() {
            candidates.push((MatchedField::Name, name));
        }
        if let Some(nip05) = profile.nip05.as_deref() {
            candidates.push((MatchedField::Nip05, nip05));
        }
        if let Some(display_name) = profile.display_name.as_deref() {
            candidates.push((MatchedField::DisplayName, display_name));
        }
        if let Some(about) = profile.about.as_deref() {
            candidates.push((MatchedField::About, about));
        }
    }

    candidates
        .into_iter()
        .filter_map(|(field, value)| {
            let value = value.to_lowercase();
            let quality = if value == query {
                MatchQuality::Exact
            } else if value.starts_with(query) {
                MatchQuality::Prefix
            } else if value.contains(query) {
                MatchQuality::Contains
            } else {
                return None;
            };
            Some(UserRecordMatch { field, quality })
        })
        .min_by_key(UserRecordMatch::rank)
}

pub(crate) fn profile_content_json(profile: &UserProfileMetadata) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    for (key, extra_value) in &profile.extra {
        if !is_known_profile_field(key) {
            value.insert(key.clone(), extra_value.clone());
        }
    }
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
    if let Some(banner) = profile.banner.as_ref().filter(|value| !value.is_empty()) {
        value.insert(
            "banner".to_owned(),
            serde_json::Value::String(banner.clone()),
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

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpoint;
    use transport_nostr_peeler::NostrTransportEvent;

    use super::*;

    /// The `matched_field` / `match_quality` wire strings are a published
    /// contract: `wn users search --json` emits them and the TUI parses them
    /// back (`cli/src/tui/model.rs`). They must survive any change to how the
    /// two are modelled in Rust, so pin the serialized form rather than the
    /// in-memory type.
    #[test]
    fn search_result_serializes_match_attribution_as_snake_case_strings() {
        let result = UserDirectorySearchResult {
            account_id_hex: "aa".repeat(32),
            npub: "npub1example".to_owned(),
            radius: 1,
            matched_field: MatchedField::DisplayName,
            match_quality: MatchQuality::Exact,
            provider_rank: None,
            profile: None,
        };

        let json = serde_json::to_value(&result).expect("search result serializes");

        assert_eq!(json["matched_field"], "display_name");
        assert_eq!(json["match_quality"], "exact");
        assert!(
            json.get("provider_rank").is_none(),
            "graph-only results must not gain discovery metadata"
        );
        assert_eq!(
            serde_json::from_value::<UserDirectorySearchResult>(json).expect("round-trips"),
            result
        );
    }

    /// Every wire spelling the CLI has ever emitted must still parse, in both
    /// directions — a rename here would silently break an installed TUI.
    #[test]
    fn every_match_attribution_spelling_round_trips() {
        for (field, wire) in [
            (MatchedField::Name, "name"),
            (MatchedField::Nip05, "nip05"),
            (MatchedField::DisplayName, "display_name"),
            (MatchedField::About, "about"),
            (MatchedField::Npub, "npub"),
            (MatchedField::Pubkey, "pubkey"),
        ] {
            assert_eq!(serde_json::to_value(field).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<MatchedField>(serde_json::json!(wire)).unwrap(),
                field
            );
        }

        for (quality, wire) in [
            (MatchQuality::Exact, "exact"),
            (MatchQuality::Prefix, "prefix"),
            (MatchQuality::Contains, "contains"),
        ] {
            assert_eq!(serde_json::to_value(quality).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<MatchQuality>(serde_json::json!(wire)).unwrap(),
                quality
            );
        }
    }

    #[test]
    fn profile_string_fields_strip_control_characters() {
        let content = serde_json::json!({
            "name": "  alice\u{1b}[2J\nadmin\u{7}  ",
            "about": "\u{0}\u{1b}",
        });

        assert_eq!(
            string_field(&content, "name").as_deref(),
            Some("alice[2Jadmin")
        );
        assert_eq!(string_field(&content, "about"), None);
    }

    #[test]
    fn malformed_profile_content_is_not_treated_as_an_existing_profile() {
        for malformed in ["not-json", "null", "[]", r#""string""#] {
            let account_id = "11".repeat(32);
            let records = vec![RelayEventRecord {
                endpoints: vec![TransportEndpoint("wss://relay.example".to_owned())],
                event: NostrTransportEvent::new_unsigned(
                    account_id.clone(),
                    KIND_NOSTR_METADATA,
                    Vec::new(),
                    malformed.to_owned(),
                ),
            }];

            assert!(
                !latest_profiles_from_records(records).contains_key(&account_id),
                "accepted malformed kind-0 content: {malformed}"
            );
        }
    }

    #[test]
    fn legacy_flattened_extra_banner_promotes_to_typed_field() {
        // Before `banner` was typed, serde's flattened `extra` map wrote it at
        // the profile's top level. New readers must promote that cached shape
        // instead of losing it on the next profile update.
        let cached: UserProfileMetadata = serde_json::from_value(serde_json::json!({
            "name": "alice",
            "banner": "https://example.test/banner.png",
            "website": "https://example.test"
        }))
        .unwrap();

        assert_eq!(
            cached.banner.as_deref(),
            Some("https://example.test/banner.png")
        );
        assert_eq!(
            cached.extra.get("website"),
            Some(&serde_json::json!("https://example.test"))
        );
        assert!(!cached.extra.contains_key("banner"));
    }

    #[test]
    fn cached_identity_projection_prefers_profile_name_over_local_label() {
        let profile = UserProfileMetadata {
            display_name: Some("Remote Name".to_owned()),
            ..UserProfileMetadata::default()
        };
        let both = cached_identity_projection(
            "requested".to_owned(),
            Some("aa".repeat(32)),
            Some(profile.clone()),
            Some("local-label".to_owned()),
        );
        assert_eq!(both.resolved_name.as_deref(), Some("Remote Name"));
        assert_eq!(both.local_label.as_deref(), Some("local-label"));
        assert!(both.profile.is_some());

        let local_only = cached_identity_projection(
            "requested".to_owned(),
            Some("aa".repeat(32)),
            None,
            Some("local-label".to_owned()),
        );
        assert_eq!(local_only.resolved_name.as_deref(), Some("local-label"));
        assert_eq!(local_only.profile, None);
    }
}
