//! User-directory record types and stateless directory-record helpers.
//!
//! Holds the public `UserDirectory*` DTOs surfaced to `marmot-uniffi`/`cli`,
//! plus conversions between cached [`UserDirectoryRecord`]s and shared
//! [`PublicDirectoryUserRecord`]s, recency selection, Nostr profile/follow-list
//! parsing, and search-match ranking. These complement the stateful directory
//! cache/sync modules in `directory/`; they hold no `MarmotApp` state and
//! operate purely on records.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};

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

/// Merge independently replaceable Nostr components without allowing a fresh
/// sibling field to drag an older component across cache boundaries.
///
/// The first record wins equal timestamps. Nostr timestamps have one-second
/// resolution, so this preserves a just-published local value against a stale
/// same-second relay copy. Fields without event recency remain from the first
/// record; public/shared records do not carry local-account or source hints.
fn merge_directory_entries(
    mut preferred: UserDirectoryRecord,
    alternate: UserDirectoryRecord,
) -> UserDirectoryRecord {
    if alternate.profile.as_ref().is_some_and(|candidate| {
        preferred
            .profile
            .as_ref()
            .is_none_or(|current| candidate.created_at > current.created_at)
    }) {
        preferred.profile = alternate.profile;
    }
    if alternate.key_package.as_ref().is_some_and(|candidate| {
        preferred
            .key_package
            .as_ref()
            .is_none_or(|current| candidate.created_at > current.created_at)
    }) {
        preferred.key_package = alternate.key_package;
    }
    if alternate.relay_lists.nip65.created_at > preferred.relay_lists.nip65.created_at {
        preferred.relay_lists.nip65 = alternate.relay_lists.nip65;
    }
    if alternate.relay_lists.inbox.created_at > preferred.relay_lists.inbox.created_at {
        preferred.relay_lists.inbox = alternate.relay_lists.inbox;
    }
    preferred.relay_lists.refresh();
    preferred
}

/// Reconcile account-cache and shared-cache directory records component-wise.
pub(crate) fn select_newer_directory_entry(
    cached: Option<UserDirectoryRecord>,
    shared: Option<UserDirectoryRecord>,
) -> Option<UserDirectoryRecord> {
    match (cached, shared) {
        (Some(cached), Some(shared)) => Some(merge_directory_entries(cached, shared)),
        (Some(entry), None) | (None, Some(entry)) => Some(entry),
        (None, None) => None,
    }
}

/// Insert a directory record or merge each timestamped component independently.
pub(crate) fn upsert_newer_directory_entry(
    entries_by_id: &mut BTreeMap<String, UserDirectoryRecord>,
    entry: UserDirectoryRecord,
) {
    match entries_by_id.entry(entry.account_id_hex.clone()) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(entry);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            let current = slot.get().clone();
            *slot.get_mut() = merge_directory_entries(current, entry);
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

/// Inclusive maximum number of unknown kind:0 fields retained on ingest.
/// Known and rejected entries do not consume a slot.
pub(crate) const MAX_EXTRA_PROFILE_FIELDS: usize = 32;

/// Inclusive maximum compact `serde_json` encoding of one unknown field key,
/// including the surrounding quotes and any escape expansion. Raw character
/// count is not the unit: a short key with quotes or backslashes can exceed
/// this after encoding.
pub(crate) const MAX_EXTRA_PROFILE_KEY_BYTES: usize = 256;

/// Inclusive maximum compact `serde_json` encoding of one unknown field value,
/// including string quotes/escapes and all nested containers and member keys.
/// Oversized values are dropped whole, never truncated.
pub(crate) const MAX_EXTRA_PROFILE_VALUE_BYTES: usize = 4096;

/// Counting `Write` sink that accepts compact JSON only while it fits `remaining`.
///
/// The next write that would exceed the budget fails immediately without
/// accepting a prefix or counting those bytes. Measurement never materializes a
/// serialized attacker-sized copy.
struct BoundedJsonWriteBudget {
    remaining: usize,
}

impl Write for BoundedJsonWriteBudget {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "compact json encoding exceeds budget",
            ));
        }
        self.remaining -= buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn compact_json_within_budget<T: Serialize + ?Sized>(value: &T, budget: usize) -> bool {
    let mut sink = BoundedJsonWriteBudget { remaining: budget };
    serde_json::to_writer(&mut sink, value).is_ok()
}

fn extra_profile_fields(content: &serde_json::Value) -> BTreeMap<String, serde_json::Value> {
    let Some(object) = content.as_object() else {
        return BTreeMap::new();
    };
    let mut extra = BTreeMap::new();
    for (key, value) in object {
        if extra.len() >= MAX_EXTRA_PROFILE_FIELDS {
            break;
        }
        if is_known_profile_field(key) {
            continue;
        }
        if !compact_json_within_budget(key, MAX_EXTRA_PROFILE_KEY_BYTES) {
            continue;
        }
        if !compact_json_within_budget(value, MAX_EXTRA_PROFILE_VALUE_BYTES) {
            continue;
        }
        extra.insert(key.clone(), value.clone());
    }
    extra
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
    use std::io::Write;

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

    fn profile_from_content(content: serde_json::Value) -> UserProfileMetadata {
        let account_id = "11".repeat(32);
        let mut event = NostrTransportEvent::new_unsigned(
            account_id,
            KIND_NOSTR_METADATA,
            Vec::new(),
            content.to_string(),
        );
        event.created_at = 1_700_000_000;
        profile_from_record(RelayEventRecord {
            endpoints: vec![TransportEndpoint("wss://relay.example".to_owned())],
            event,
        })
        .expect("object kind:0 content parses")
        .1
    }

    fn ascii_xs(count: usize) -> String {
        "x".repeat(count)
    }

    /// Braces, encoded keys, colons, values, and commas at maximum occupancy.
    const MAX_RETAINED_EXTRA_PROFILE_JSON_BYTES: usize = 2
        + MAX_EXTRA_PROFILE_FIELDS
            * (MAX_EXTRA_PROFILE_KEY_BYTES + 1 + MAX_EXTRA_PROFILE_VALUE_BYTES)
        + MAX_EXTRA_PROFILE_FIELDS.saturating_sub(1);

    #[test]
    fn bounded_json_write_budget_rejects_the_write_that_would_exceed() {
        let mut sink = BoundedJsonWriteBudget { remaining: 4 };
        assert_eq!(sink.write(b"abcd").unwrap(), 4);
        assert_eq!(sink.remaining, 0);
        assert!(sink.write(b"x").is_err());
        assert_eq!(sink.remaining, 0, "a rejected write must not be counted");

        let mut sink = BoundedJsonWriteBudget { remaining: 3 };
        assert!(sink.write(b"abcd").is_err());
        assert_eq!(
            sink.remaining, 3,
            "an oversized write must not consume any budget"
        );

        let mut sink = BoundedJsonWriteBudget { remaining: 5 };
        assert_eq!(sink.write(b"ab").unwrap(), 2);
        assert_eq!(sink.write(b"cd").unwrap(), 2);
        assert_eq!(sink.remaining, 1);
        assert!(sink.write(b"ef").is_err());
        assert_eq!(sink.remaining, 1);
        assert_eq!(sink.write(b"e").unwrap(), 1);
        assert_eq!(sink.remaining, 0);
    }

    #[test]
    fn compact_json_budget_uses_encoded_bytes_not_raw_character_count() {
        assert!(compact_json_within_budget(
            &ascii_xs(254),
            MAX_EXTRA_PROFILE_KEY_BYTES
        ));
        assert!(!compact_json_within_budget(
            &ascii_xs(255),
            MAX_EXTRA_PROFILE_KEY_BYTES
        ));

        let quotes_at_limit = "\"".repeat(2047);
        let quotes_over = "\"".repeat(2048);
        assert!(compact_json_within_budget(
            &quotes_at_limit,
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));
        assert!(!compact_json_within_budget(
            &quotes_over,
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));

        let backslashes_at_limit = "\\".repeat(2047);
        assert!(compact_json_within_budget(
            &backslashes_at_limit,
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));
        assert!(!compact_json_within_budget(
            &format!("{backslashes_at_limit}\\"),
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));

        let newlines_at_limit = "\n".repeat(2047);
        assert_eq!(
            serde_json::to_vec(&newlines_at_limit).unwrap().len(),
            MAX_EXTRA_PROFILE_VALUE_BYTES
        );
        assert!(compact_json_within_budget(
            &newlines_at_limit,
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));
        assert!(!compact_json_within_budget(
            &format!("{newlines_at_limit}\n"),
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));
        // SOH encodes as `\u0001` (6 bytes). 683 raw chars are far below a
        // 4096-character cap but still miss the encoded-byte budget.
        let soh_over = "\u{0001}".repeat(683);
        assert!(soh_over.chars().count() < MAX_EXTRA_PROFILE_VALUE_BYTES);
        assert!(!compact_json_within_budget(
            &soh_over,
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));

        let utf8_at_limit = "é".repeat(2047);
        assert_eq!(
            serde_json::to_vec(&utf8_at_limit).unwrap().len(),
            MAX_EXTRA_PROFILE_VALUE_BYTES
        );
        assert!(compact_json_within_budget(
            &utf8_at_limit,
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));
        assert!(!compact_json_within_budget(
            &format!("{utf8_at_limit}é"),
            MAX_EXTRA_PROFILE_VALUE_BYTES
        ));
    }

    #[test]
    fn extra_profile_fields_preserve_accepted_json_types_and_drop_oversized_entries() {
        let huge = ascii_xs(2 * 1024 * 1024);
        let nested_over = serde_json::json!({
            "leaf": ascii_xs(MAX_EXTRA_PROFILE_VALUE_BYTES)
        });
        let array_over = serde_json::json!([ascii_xs(MAX_EXTRA_PROFILE_VALUE_BYTES)]);
        let oversized_key = ascii_xs(255);
        let profile = profile_from_content(serde_json::json!({
            "name": "alice",
            "displayName": "Alice",
            "banner": "https://example.test/banner.png",
            "website": "https://example.test",
            "bot": false,
            "count": 7,
            "missing": null,
            "tags": ["a", "b"],
            "nested": {"ok": true, "n": 1},
            "unicode": "café ☕",
            "custom_blob": huge,
            "nested_blob": nested_over,
            "array_blob": array_over,
            oversized_key.clone(): "tiny",
            "later": "kept",
            "created_at": 42,
            "source_relays": ["wss://spoof.example"]
        }));

        assert_eq!(profile.name.as_deref(), Some("alice"));
        assert_eq!(profile.display_name.as_deref(), Some("Alice"));
        assert_eq!(
            profile.banner.as_deref(),
            Some("https://example.test/banner.png")
        );
        assert_eq!(profile.created_at, 1_700_000_000);
        assert_eq!(
            profile.source_relays,
            vec!["wss://relay.example".to_owned()]
        );
        assert_eq!(
            profile.extra.get("website"),
            Some(&serde_json::json!("https://example.test"))
        );
        assert_eq!(profile.extra.get("bot"), Some(&serde_json::json!(false)));
        assert_eq!(profile.extra.get("count"), Some(&serde_json::json!(7)));
        assert_eq!(profile.extra.get("missing"), Some(&serde_json::json!(null)));
        assert_eq!(
            profile.extra.get("tags"),
            Some(&serde_json::json!(["a", "b"]))
        );
        assert_eq!(
            profile.extra.get("nested"),
            Some(&serde_json::json!({"ok": true, "n": 1}))
        );
        assert_eq!(
            profile.extra.get("unicode"),
            Some(&serde_json::json!("café ☕"))
        );
        assert_eq!(profile.extra.get("later"), Some(&serde_json::json!("kept")));
        assert!(!profile.extra.contains_key("custom_blob"));
        assert!(!profile.extra.contains_key("nested_blob"));
        assert!(!profile.extra.contains_key("array_blob"));
        assert!(!profile.extra.contains_key(&oversized_key));
        assert!(!profile.extra.contains_key("created_at"));
        assert!(!profile.extra.contains_key("source_relays"));
        assert!(!profile.extra.contains_key("name"));
        assert!(!profile.extra.contains_key("banner"));
        assert!(!profile.extra.contains_key("displayName"));
    }

    #[test]
    fn extra_profile_fields_keep_exactly_at_limit_and_drop_one_byte_over() {
        let key_at_limit = ascii_xs(254);
        let key_over = ascii_xs(255);
        let value_at_limit = ascii_xs(MAX_EXTRA_PROFILE_VALUE_BYTES - 2);
        let value_over = ascii_xs(MAX_EXTRA_PROFILE_VALUE_BYTES - 1);
        assert_eq!(
            serde_json::to_vec(&key_at_limit).unwrap().len(),
            MAX_EXTRA_PROFILE_KEY_BYTES
        );
        assert_eq!(
            serde_json::to_vec(&key_over).unwrap().len(),
            MAX_EXTRA_PROFILE_KEY_BYTES + 1
        );
        assert_eq!(
            serde_json::to_vec(&value_at_limit).unwrap().len(),
            MAX_EXTRA_PROFILE_VALUE_BYTES
        );
        assert_eq!(
            serde_json::to_vec(&value_over).unwrap().len(),
            MAX_EXTRA_PROFILE_VALUE_BYTES + 1
        );

        let profile = profile_from_content(serde_json::json!({
            key_at_limit.clone(): "ok",
            key_over.clone(): "tiny",
            "value_ok": value_at_limit.clone(),
            "value_over": value_over
        }));

        assert_eq!(
            profile.extra.get(&key_at_limit),
            Some(&serde_json::json!("ok"))
        );
        assert!(!profile.extra.contains_key(&key_over));
        assert_eq!(
            profile.extra.get("value_ok"),
            Some(&serde_json::Value::String(value_at_limit))
        );
        assert!(!profile.extra.contains_key("value_over"));
    }

    #[test]
    fn extra_profile_fields_quota_skips_known_and_oversized_without_consuming_slots() {
        assert!(extra_profile_fields(&serde_json::json!({})).is_empty());

        let mut at_limit = serde_json::Map::new();
        for index in 0..MAX_EXTRA_PROFILE_FIELDS {
            at_limit.insert(format!("k{index:02}"), serde_json::json!(index));
        }
        let at_limit_profile = profile_from_content(serde_json::Value::Object(at_limit.clone()));
        assert_eq!(at_limit_profile.extra.len(), MAX_EXTRA_PROFILE_FIELDS);
        let encoded = serde_json::to_vec(&at_limit_profile.extra).unwrap();
        assert!(encoded.len() <= MAX_RETAINED_EXTRA_PROFILE_JSON_BYTES);
        let repeated = profile_from_content(serde_json::Value::Object(at_limit.clone()));
        assert_eq!(repeated.extra, at_limit_profile.extra);

        let mut over = at_limit;
        over.insert(
            format!("k{MAX_EXTRA_PROFILE_FIELDS:02}"),
            serde_json::json!("overflow"),
        );
        over.insert("name".to_owned(), serde_json::json!("typed"));
        over.insert("custom_blob".to_owned(), serde_json::json!(ascii_xs(8000)));
        let over_profile = profile_from_content(serde_json::Value::Object(over));
        assert_eq!(over_profile.extra.len(), MAX_EXTRA_PROFILE_FIELDS);
        assert_eq!(over_profile.name.as_deref(), Some("typed"));
        assert!(!over_profile.extra.contains_key("custom_blob"));
        assert!(
            !over_profile
                .extra
                .contains_key(&format!("k{MAX_EXTRA_PROFILE_FIELDS:02}"))
        );
        for index in 0..MAX_EXTRA_PROFILE_FIELDS {
            assert_eq!(
                over_profile.extra.get(&format!("k{index:02}")),
                Some(&serde_json::json!(index))
            );
        }
        let encoded = serde_json::to_vec(&over_profile.extra).unwrap();
        assert!(encoded.len() <= MAX_RETAINED_EXTRA_PROFILE_JSON_BYTES);
        assert_eq!(
            profile_content_json(&over_profile)["name"],
            serde_json::json!("typed")
        );
    }

    #[test]
    fn extra_profile_fields_do_not_enable_unbounded_json_recursion() {
        let mut deep = String::from("null");
        for _ in 0..200 {
            deep = format!("[{deep}]");
        }
        let content =
            format!(r#"{{"name":"alice","deep":{deep},"website":"https://example.test"}}"#);
        assert!(
            serde_json::from_str::<serde_json::Value>(&content).is_err(),
            "ingest must keep serde_json's default recursion rejection"
        );
        let account_id = "11".repeat(32);
        let mut event = NostrTransportEvent::new_unsigned(
            account_id.clone(),
            KIND_NOSTR_METADATA,
            Vec::new(),
            content,
        );
        event.created_at = 1_700_000_000;
        assert!(
            profile_from_record(RelayEventRecord {
                endpoints: vec![TransportEndpoint("wss://relay.example".to_owned())],
                event,
            })
            .is_none(),
            "excessively nested kind:0 content must not become a profile"
        );
    }

    #[test]
    fn known_profile_fields_remain_character_capped_including_banner_alias() {
        let oversized = format!("{}!", ascii_xs(MAX_PROFILE_FIELD_CHARS));
        let profile = profile_from_content(serde_json::json!({
            "name": oversized,
            "displayName": oversized,
            "banner": oversized,
            "about": oversized
        }));
        assert_eq!(
            profile.name.as_deref().map(|value| value.chars().count()),
            Some(MAX_PROFILE_FIELD_CHARS)
        );
        assert_eq!(
            profile
                .display_name
                .as_deref()
                .map(|value| value.chars().count()),
            Some(MAX_PROFILE_FIELD_CHARS)
        );
        assert_eq!(
            profile.banner.as_deref().map(|value| value.chars().count()),
            Some(MAX_PROFILE_FIELD_CHARS)
        );
        assert_eq!(
            profile.about.as_deref().map(|value| value.chars().count()),
            Some(MAX_PROFILE_FIELD_CHARS)
        );
    }

    #[test]
    fn flattened_profile_round_trip_preserves_retained_extensions() {
        let profile = profile_from_content(serde_json::json!({
            "name": "alice",
            "website": "https://example.test",
            "bot": false
        }));
        let json = serde_json::to_value(&profile).unwrap();
        let round_trip: UserProfileMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, profile);
        let content = profile_content_json(&profile);
        assert_eq!(content["name"], "alice");
        assert_eq!(content["website"], "https://example.test");
        assert_eq!(content["bot"], false);
    }
}
