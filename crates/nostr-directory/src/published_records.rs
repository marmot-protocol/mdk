//! Records other accounts publish: relay lists and KeyPackages.
//!
//! Typed relay-list status, the directory's freshness and selection primitives,
//! and stateless KeyPackage handling: parsing and tag validation, cached-entry
//! checks, ranking, selection and revocation evidence. They hold no
//! `MarmotApp` state. The account's own KeyPackage inventory stays in
//! `crate::key_package_records`.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cgka_engine::key_package::{KeyPackageMetadata, key_package_metadata};
use cgka_traits::MessageId;
use cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START;
use cgka_traits::engine::KeyPackage;
use cgka_traits::group::ProtocolProfile;
use serde::{Deserialize, Serialize};
use transport_nostr_adapter::parse_nip65_relay_set;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
    RELAY_REPLAY_PAGE_LIMIT,
};
use transport_nostr_peeler::NostrTransportEvent;

use super::unix_now_seconds;
use crate::error::{DirectoryError, MissingKeyPackageReason};
use crate::{DirectoryKeyPackage, UserDirectoryRecord};
use transport_nostr::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRelayListStatus {
    pub complete: bool,
    pub missing: Vec<MissingRelayListKind>,
    pub default_relays: Vec<String>,
    pub bootstrap_relays: Vec<String>,
    pub nip65: AccountRelayListState,
    pub inbox: AccountRelayListState,
}

impl AccountRelayListStatus {
    pub fn empty() -> Self {
        let mut status = Self {
            complete: false,
            missing: Vec::new(),
            default_relays: Vec::new(),
            bootstrap_relays: Vec::new(),
            nip65: AccountRelayListState {
                kind: KIND_NIP65_RELAY_LIST,
                created_at: 0,
                relays: Vec::new(),
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            },
            inbox: AccountRelayListState {
                kind: KIND_MARMOT_INBOX_RELAY_LIST,
                created_at: 0,
                relays: Vec::new(),
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            },
        };
        status.refresh();
        status
    }

    pub fn refresh(&mut self) {
        self.default_relays = self.nip65.relays.clone();
        self.missing = Vec::new();
        if self.nip65.relays.is_empty() {
            self.missing.push(MissingRelayListKind::Nip65);
        }
        if self.inbox.relays.is_empty() {
            self.missing.push(MissingRelayListKind::Inbox);
        }
        self.complete = self.missing.is_empty();
    }
}

/// A relay list the account is missing. Typed so FFI clients can localize
/// each kind without parsing protocol-jargon strings (mdk#565).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MissingRelayListKind {
    /// NIP-65 relay list (kind 10002) — where this account publishes
    /// ("outbox"/write-side). Missing when the account has no NIP-65 relays.
    #[serde(rename = "nip65")]
    Nip65,
    /// Marmot inbox relay list (kind 10050) — where this account receives
    /// ("inbox"/read-side). Missing when the account has no inbox relays.
    #[serde(rename = "inbox")]
    Inbox,
}

impl MissingRelayListKind {
    /// Stable lowercase token, kept for the existing CLI `--json` / plain
    /// output contract (`"missing": ["nip65","inbox"]`). NOT a localization
    /// key — clients localize from the enum variant, not this string.
    pub fn token(self) -> &'static str {
        match self {
            Self::Nip65 => "nip65",
            Self::Inbox => "inbox",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRelayListState {
    pub kind: u64,
    /// Timestamp of the replaceable event that produced this cached state.
    ///
    /// Zero denotes a legacy or caller-constructed state with unknown recency.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub created_at: u64,
    /// Direction-appropriate relay targets for this list.
    ///
    /// For NIP-65 kind 10002 this is specifically the write-capable set:
    /// unmarked and `write` entries, excluding `read`-only entries. For the
    /// Marmot inbox list this is the declared inbox relay set.
    pub relays: Vec<String>,
    /// NIP-65 read-capable relays, including unmarked entries.
    ///
    /// Empty for non-NIP-65 lists and for cache records written before
    /// directional roles were persisted.
    #[serde(default)]
    pub read_relays: Vec<String>,
    /// NIP-65 write-capable relays, including unmarked entries.
    ///
    /// This is the explicit directional counterpart of the compatibility
    /// `relays` field. Empty for non-NIP-65 lists and for legacy cache records.
    #[serde(default)]
    pub write_relays: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedKeyPackage {
    pub account_id_hex: String,
    pub key_package: KeyPackage,
    pub key_package_id: String,
    pub key_package_ref_hex: String,
    pub key_package_event_id: String,
    pub created_at: u64,
    pub source_relays: Vec<String>,
    pub relay_lists: AccountRelayListStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryFreshness {
    /// The selection time, in Unix seconds.
    pub(crate) now: u64,
    pub(crate) max_created_at: u64,
}

impl DirectoryFreshness {
    pub(crate) fn from_now(max_future_skew: Duration) -> Self {
        Self::at(unix_now_seconds(), max_future_skew)
    }

    pub(crate) fn at(now: u64, max_future_skew: Duration) -> Self {
        Self {
            now,
            max_created_at: now.saturating_add(max_future_skew.as_secs()),
        }
    }

    pub(crate) fn accepts(self, record: &RelayEventRecord) -> bool {
        record.event.created_at <= self.max_created_at
    }

    /// Published no more than [`KEY_PACKAGE_FRESHNESS`] before selection.
    fn is_fresh_key_package(self, created_at: u64) -> bool {
        created_at.saturating_add(KEY_PACKAGE_FRESHNESS.as_secs()) >= self.now
    }
}

#[derive(Debug)]
pub(crate) struct DirectorySelection<T> {
    pub(crate) value: T,
    pub(crate) rejected_future: bool,
}

pub fn sort_directory_records(records: &mut [RelayEventRecord]) {
    records.sort_by(|a, b| {
        a.event
            .created_at
            .cmp(&b.event.created_at)
            .then_with(|| a.event.id.cmp(&b.event.id))
    });
}

#[cfg(any(test, feature = "test-support"))]
pub fn relays_from_relay_list_event(event: &NostrTransportEvent) -> Vec<String> {
    relay_list_state_from_event(event)
        .map(|state| state.relays)
        .unwrap_or_default()
}

pub fn relay_list_state_from_event(event: &NostrTransportEvent) -> Option<AccountRelayListState> {
    match event.kind {
        KIND_NIP65_RELAY_LIST => {
            let relay_set = parse_nip65_relay_set(event);
            let read_relays = relay_set
                .read_relays
                .into_iter()
                .map(|endpoint| endpoint.0)
                .collect::<Vec<_>>();
            let write_relays = relay_set
                .write_relays
                .into_iter()
                .map(|endpoint| endpoint.0)
                .collect::<Vec<_>>();
            Some(AccountRelayListState {
                kind: KIND_NIP65_RELAY_LIST,
                created_at: event.created_at,
                relays: write_relays.clone(),
                read_relays,
                write_relays,
            })
        }
        KIND_MARMOT_INBOX_RELAY_LIST => {
            let mut relays = Vec::new();
            for tag in &event.tags {
                if tag.first().is_some_and(|name| name == "relay")
                    && let Some(value) = tag.get(1).filter(|value| !value.trim().is_empty())
                {
                    push_unique_strings(&mut relays, [value.clone()]);
                }
            }
            Some(AccountRelayListState {
                kind: KIND_MARMOT_INBOX_RELAY_LIST,
                created_at: event.created_at,
                relays,
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            })
        }
        _ => None,
    }
}

pub fn push_unique_strings(values: &mut Vec<String>, candidates: impl IntoIterator<Item = String>) {
    for candidate in candidates {
        if !values.contains(&candidate) {
            values.push(candidate);
        }
    }
}

/// Evidence from a complete supplementary lookup, used only to restrict the
/// direct diagnostic API's existing future-record cache fallback.
pub(crate) struct KeyPackageRecoveryEvidence {
    account: String,
    winners: Vec<NostrTransportEvent>,
    deletions: Vec<NostrTransportEvent>,
}

/// Public lookup target metadata; deliberately excludes KeyPackage bytes.
#[derive(Clone)]
pub(crate) struct KeyPackageRecoveryTarget {
    pub(crate) event_id: String,
    pub(crate) slot: String,
    pub(crate) created_at: u64,
}

impl KeyPackageRecoveryTarget {
    pub(crate) fn from_fetched(fetched: &FetchedKeyPackage) -> Self {
        Self {
            event_id: fetched.key_package_event_id.clone(),
            slot: fetched.key_package_id.clone(),
            created_at: fetched.created_at,
        }
    }
    pub(crate) fn from_cached(cached: &DirectoryKeyPackage) -> Self {
        Self {
            event_id: cached.key_package_event_id.trim().to_ascii_lowercase(),
            slot: cached.key_package_id.clone(),
            created_at: cached.created_at,
        }
    }
}

impl KeyPackageRecoveryEvidence {
    pub(crate) fn allows_cached(&self, cached: &DirectoryKeyPackage) -> bool {
        self.allows_target(&KeyPackageRecoveryTarget::from_cached(cached))
    }
    pub(crate) fn allows_target(&self, target: &KeyPackageRecoveryTarget) -> bool {
        !package_is_deleted(
            &self.account,
            &target.event_id,
            &target.slot,
            target.created_at,
            &self.deletions,
        ) && !self.winners.iter().any(|winner| {
            winner.tag_value("d") == Some(target.slot.as_str())
                && newest_publication_first(winner, target.created_at, &target.event_id).is_lt()
        })
    }
}

/// Slot order: the later `created_at` first and, on a tie, the lower event id,
/// which NIP-01 keeps as the slot's current publication.
fn newest_publication_first(
    event: &NostrTransportEvent,
    created_at: u64,
    event_id: &str,
) -> std::cmp::Ordering {
    created_at
        .cmp(&event.created_at)
        .then_with(|| event.id.as_str().cmp(event_id))
}

/// Collapse fresh slot winners before applying deletions, retaining invalid,
/// obsolete and incompatible replacements as barriers against older material.
pub(crate) fn without_revoked_slot_winners(
    account: &str,
    mut records: Vec<RelayEventRecord>,
    deletions: &[RelayEventRecord],
    freshness: DirectoryFreshness,
) -> (Vec<RelayEventRecord>, KeyPackageRecoveryEvidence) {
    records.sort_by(|a, b| newest_publication_first(&a.event, b.event.created_at, &b.event.id));
    let deletions = verified_deletions(account, deletions);
    let mut slots = BTreeSet::new();
    let mut winners = Vec::new();
    records.retain(|record| {
        let event = &record.event;
        if event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != account {
            return false;
        }
        if freshness.accepts(record) {
            if let Some(slot) = event.tag_value("d").filter(|slot| !slot.is_empty())
                && !slots.insert(slot.to_owned())
            {
                return false;
            }
            winners.push(event.clone());
        }
        !package_is_deleted(
            account,
            &event.id,
            event.tag_value("d").unwrap_or_default(),
            event.created_at,
            &deletions,
        )
    });
    (
        records,
        KeyPackageRecoveryEvidence {
            account: account.to_owned(),
            winners,
            deletions,
        },
    )
}

/// The account's signed kind 5 requests among `records`.
fn verified_deletions(account: &str, records: &[RelayEventRecord]) -> Vec<NostrTransportEvent> {
    records
        .iter()
        .filter(|record| {
            record.event.kind == 5
                && record.event.pubkey == account
                && record.event.to_verified_nostr_event().is_ok()
        })
        .map(|record| record.event.clone())
        .collect()
}

pub(crate) fn package_is_deleted(
    account: &str,
    event_id: &str,
    slot: &str,
    created_at: u64,
    deletions: &[NostrTransportEvent],
) -> bool {
    deletions.iter().any(|deletion| {
        deletion
            .tag_values("e")
            .iter()
            .any(|reference| !event_id.is_empty() && reference.eq_ignore_ascii_case(event_id))
            || (created_at <= deletion.created_at
                && deletion.tag_values("a").iter().any(|reference| {
                    let mut parts = reference.splitn(3, ':');
                    parts.next().and_then(|kind| kind.parse::<u16>().ok())
                        == Some(KIND_MARMOT_KEY_PACKAGE as u16)
                        && parts
                            .next()
                            .is_some_and(|author| author.eq_ignore_ascii_case(account))
                        && parts.next() == Some(slot)
                }))
    })
}

pub(crate) fn merge_relay_list_status(
    mut current: AccountRelayListStatus,
    candidate: AccountRelayListStatus,
) -> AccountRelayListStatus {
    if candidate.nip65.created_at > current.nip65.created_at
        || (candidate.nip65.created_at == 0
            && current.nip65.created_at == 0
            && current.nip65.relays.is_empty()
            && !candidate.nip65.relays.is_empty())
    {
        current.nip65 = candidate.nip65;
    }
    if candidate.inbox.created_at > current.inbox.created_at
        || (candidate.inbox.created_at == 0
            && current.inbox.created_at == 0
            && current.inbox.relays.is_empty()
            && !candidate.inbox.relays.is_empty())
    {
        current.inbox = candidate.inbox;
    }
    push_unique_strings(&mut current.bootstrap_relays, candidate.bootstrap_relays);
    current.refresh();
    current
}

pub fn relay_list_status_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
) -> AccountRelayListStatus {
    sort_directory_records(&mut records);
    let mut status = AccountRelayListStatus::empty();
    let mut seen_nip65 = false;
    let mut seen_inbox = false;
    for record in records {
        if record.event.pubkey != account_id_hex {
            continue;
        }
        let Some(state) = relay_list_state_from_event(&record.event) else {
            continue;
        };
        match record.event.kind {
            KIND_NIP65_RELAY_LIST if !seen_nip65 || state.created_at > status.nip65.created_at => {
                status.nip65 = state;
                seen_nip65 = true;
            }
            KIND_MARMOT_INBOX_RELAY_LIST
                if !seen_inbox || state.created_at > status.inbox.created_at =>
            {
                status.inbox = state;
                seen_inbox = true;
            }
            KIND_NIP65_RELAY_LIST | KIND_MARMOT_INBOX_RELAY_LIST => {}
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

pub fn relay_list_queries(account_id_hex: String) -> Vec<DirectoryEventQuery> {
    [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
        .into_iter()
        .map(|kind| DirectoryEventQuery::new(kind, vec![account_id_hex.clone()], 12))
        .collect()
}

/// The most KeyPackages one account contributes to one Commit
/// (`foundation/key-packages.md`, "Selection and lifecycle").
pub const MAX_KEY_PACKAGES_PER_ACCOUNT: usize = 20;
/// A KeyPackage published no longer than this before selection is fresh.
pub const KEY_PACKAGE_FRESHNESS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// KeyPackage events, and separately deletion requests, read in one lookup:
/// one relay page each. Relays keep one event per slot and each slot is one
/// device, so every slot of a normal account fits, along with its deletion
/// requests. A page that comes back full fails the lookup instead of ranking
/// without what lies past it ([`key_package_read_page_full`]). Only the
/// account's own key can publish into its slots or delete them, so only the
/// account itself can make itself uninvitable this way.
pub(crate) const KEY_PACKAGE_READ_PAGE: usize = RELAY_REPLAY_PAGE_LIMIT;

/// The KeyPackage events and the deletion requests read alongside them.
pub(crate) fn key_package_queries(authors: Vec<String>) -> Vec<DirectoryEventQuery> {
    vec![
        DirectoryEventQuery::new(
            KIND_MARMOT_KEY_PACKAGE,
            authors.clone(),
            KEY_PACKAGE_READ_PAGE,
        ),
        DirectoryEventQuery::key_package_deletions(authors, KEY_PACKAGE_READ_PAGE),
    ]
}

/// Whether some relay returned a full page of `account`'s KeyPackages or of
/// its deletion requests. Nothing past the page was read: an older slot may
/// outrank every one read, and an older request may cover a slot that still
/// selects.
pub(crate) fn key_package_read_page_full(account: &str, records: &[RelayEventRecord]) -> bool {
    let mut pages = std::collections::BTreeMap::<_, BTreeSet<_>>::new();
    for record in records.iter().filter(|record| {
        record.event.pubkey == account
            && (record.event.kind == KIND_MARMOT_KEY_PACKAGE || record.event.kind == 5)
    }) {
        for endpoint in &record.endpoints {
            pages
                .entry((endpoint.as_str(), record.event.kind))
                .or_default()
                .insert(record.event.id.as_str());
        }
    }
    pages.values().any(|ids| ids.len() >= KEY_PACKAGE_READ_PAGE)
}

/// One account's selected KeyPackages, best first. `legacy_slots` only
/// explains an empty selection; it never makes a legacy publication a join
/// candidate.
pub struct KeyPackageSelection {
    pub value: Vec<FetchedKeyPackage>,
    pub(crate) rejected_future: bool,
    pub legacy_slots: bool,
}

impl KeyPackageSelection {
    /// Call only after the lookup that produced these records completed: an
    /// incomplete search can explain neither absence nor obsolescence.
    pub fn into_value_or_missing(
        self,
        account_id_hex: &str,
    ) -> Result<Vec<FetchedKeyPackage>, DirectoryError> {
        if !self.value.is_empty() {
            return Ok(self.value);
        }
        // A future-dated slot may be a clock-skewed current publication.
        let reason = if self.legacy_slots && !self.rejected_future {
            MissingKeyPackageReason::ObsoleteOnly
        } else {
            MissingKeyPackageReason::NotFound
        };
        Err(DirectoryError::MissingKeyPackage {
            account: account_id_hex.to_owned(),
            reason,
        })
    }
}

/// A validated candidate and what ranks it.
struct RankedKeyPackage {
    fetched: FetchedKeyPackage,
    last_resort: bool,
    signature_key: Vec<u8>,
    key_package_ref: Vec<u8>,
}

/// Select the account's KeyPackages to add (`foundation/key-packages.md`,
/// "Selection and lifecycle"; `transports/nostr.md`, "KeyPackage
/// publication" and "Slot deletion").
///
/// - Each `d` slot's current publication is its newest fresh event. It
///   supersedes the slot even when it is invalid or deleted: falling back
///   within that slot could invite a package whose private material has
///   already been retired.
/// - A candidate a deletion request among `records` covers, by the slot's
///   address or by the event's id, is skipped.
/// - Malformed, legacy, expired and, with `requirements`, incompatible
///   candidates are rejected before ranking.
/// - Ranking: non-last-resort first, then the most recently published, then
///   the lower KeyPackageRef. Of candidates sharing a leaf signature key, one
///   device publishing in several slots, only the highest-ranked stays: a
///   Commit cannot add two leaves with one key.
/// - Every fresh candidate is selected, at most
///   [`MAX_KEY_PACKAGES_PER_ACCOUNT`]; with none fresh, the single
///   highest-ranked one.
///
/// With no candidate left, the newest rejection is the error.
pub fn select_key_packages_from_records(
    account_id_hex: &str,
    records: &[RelayEventRecord],
    freshness: DirectoryFreshness,
    requirements: Option<&cgka_engine::key_package::KeyPackageRequirements>,
) -> Result<KeyPackageSelection, DirectoryError> {
    let SlotCandidates {
        mut candidates,
        newest_error,
        rejected_future,
        legacy_slots,
    } = slot_candidates(account_id_hex, records, freshness, requirements);
    if candidates.is_empty()
        && let Some(error) = newest_error
    {
        return Err(error);
    }
    candidates.sort_by(|a, b| {
        a.last_resort
            .cmp(&b.last_resort)
            .then_with(|| b.fetched.created_at.cmp(&a.fetched.created_at))
            .then_with(|| a.key_package_ref.cmp(&b.key_package_ref))
    });
    let has_fresh = candidates
        .iter()
        .any(|candidate| freshness.is_fresh_key_package(candidate.fetched.created_at));
    let mut signature_keys = BTreeSet::new();
    let value = candidates
        .into_iter()
        .filter(|candidate| {
            !has_fresh || freshness.is_fresh_key_package(candidate.fetched.created_at)
        })
        .filter(|candidate| signature_keys.insert(candidate.signature_key.clone()))
        .take(if has_fresh {
            MAX_KEY_PACKAGES_PER_ACCOUNT
        } else {
            1
        })
        .map(|candidate| candidate.fetched)
        .collect();
    Ok(KeyPackageSelection {
        value,
        rejected_future,
        legacy_slots,
    })
}

/// Every slot's candidate, before ranking: its newest publication that is
/// not deleted, valid, current profile and, with `requirements`, compatible.
struct SlotCandidates {
    candidates: Vec<RankedKeyPackage>,
    /// The newest publication's rejection, of every slot rejected.
    newest_error: Option<DirectoryError>,
    rejected_future: bool,
    legacy_slots: bool,
}

fn slot_candidates(
    account_id_hex: &str,
    records: &[RelayEventRecord],
    freshness: DirectoryFreshness,
    requirements: Option<&cgka_engine::key_package::KeyPackageRequirements>,
) -> SlotCandidates {
    let deletions = verified_deletions(account_id_hex, records);
    let mut records = records
        .iter()
        .filter(|record| {
            record.event.kind == KIND_MARMOT_KEY_PACKAGE && record.event.pubkey == account_id_hex
        })
        .collect::<Vec<_>>();
    records.sort_by(|a, b| newest_publication_first(&a.event, b.event.created_at, &b.event.id));
    let mut rejected_future = false;
    let mut newest_error = None;
    let mut slots = BTreeSet::new();
    let mut legacy_slots = false;
    let mut candidates = Vec::new();
    for record in records {
        if !freshness.accepts(record) {
            rejected_future = true;
            continue;
        }
        let slot = record.event.tag_value("d").unwrap_or_default();
        if !slot.is_empty() && !slots.insert(slot.to_owned()) {
            continue;
        }
        if package_is_deleted(
            account_id_hex,
            &record.event.id,
            slot,
            record.event.created_at,
            &deletions,
        ) {
            continue;
        }
        let (fetched, metadata) = match key_package_and_metadata_from_borrowed_record(record) {
            Ok((fetched, metadata))
                if fetched.key_package.protocol_profile == ProtocolProfile::Current =>
            {
                (fetched, metadata)
            }
            Ok(_) => continue,
            // A legacy slot still supersedes its older publications, but is
            // neither a candidate nor a validation error: it cannot mask a
            // current slot's rejection, and only a completed lookup reports it.
            Err(_) if is_legacy_key_package_record(record) => {
                legacy_slots = true;
                continue;
            }
            Err(error) => {
                newest_error.get_or_insert(error);
                continue;
            }
        };
        if let Some(requirements) = requirements
            && let Err(error) = requirements.validate(&fetched.key_package)
        {
            newest_error.get_or_insert(DirectoryError::KeyPackageRequirements(error));
            continue;
        }
        let Ok(key_package_ref) = hex::decode(&metadata.key_package_ref_hex) else {
            continue;
        };
        candidates.push(RankedKeyPackage {
            fetched,
            last_resort: metadata.last_resort,
            signature_key: metadata.leaf_signature_key,
            key_package_ref,
        });
    }
    SlotCandidates {
        candidates,
        newest_error,
        rejected_future,
        legacy_slots,
    }
}

/// One read of every KeyPackage slot of one account, for its own devices'
/// new-sign-in check (mdk#2628 item 3.2).
#[derive(Clone, Debug)]
pub struct AccountKeyPackageSlots {
    /// Each slot's newest publication that is fresh and valid by the
    /// inviter's rules ([`select_key_packages_from_records`]), with its
    /// self-reported client name. Unlike an inviter's selection, every such
    /// slot is here: none is capped, or dropped for sharing a signature key
    /// with another.
    pub key_packages: Vec<SlotKeyPackage>,
    /// The `d` of every KeyPackage publication of the account the read
    /// returned, whether or not it counts: which slots exist, whatever their
    /// publications' times.
    pub returned_slots: BTreeSet<String>,
    /// Every relay reached its end of stored events and no page came back
    /// full, so a slot missing here is not signed in.
    pub complete: bool,
    /// The read is complete or returned some of the account's publications.
    /// A read that reached no relay proves nothing.
    pub reached: bool,
}

#[derive(Clone, Debug)]
pub struct SlotKeyPackage {
    pub fetched: FetchedKeyPackage,
    /// The `client` tag, read as every MDK reader reads it.
    pub client: Option<String>,
}

/// [`AccountKeyPackageSlots`] from one read of `account`'s KeyPackages and
/// deletion requests. It drops whatever an inviter would: a deleted,
/// invalid, legacy or future-dated publication, and every slot whose newest
/// publication is one of those. Only fresh KeyPackages count.
pub fn account_key_package_slots_from_records(
    account: &str,
    records: &[RelayEventRecord],
    complete: bool,
    freshness: DirectoryFreshness,
) -> AccountKeyPackageSlots {
    let complete = complete && !key_package_read_page_full(account, records);
    let reached = complete || records.iter().any(|record| record.event.pubkey == account);
    let key_packages = slot_candidates(account, records, freshness, None)
        .candidates
        .into_iter()
        .map(|candidate| candidate.fetched)
        .filter(|fetched| freshness.is_fresh_key_package(fetched.created_at))
        .map(|fetched| {
            let client = records
                .iter()
                .find(|record| record.event.id == fetched.key_package_event_id)
                .and_then(|record| transport_nostr_adapter::key_package_client_name(&record.event))
                .map(str::to_owned);
            SlotKeyPackage { fetched, client }
        })
        .collect();
    let returned_slots = records
        .iter()
        .filter(|record| {
            record.event.kind == KIND_MARMOT_KEY_PACKAGE && record.event.pubkey == account
        })
        .filter_map(|record| record.event.tag_value("d"))
        .filter(|slot| !slot.is_empty())
        .map(str::to_owned)
        .collect();
    AccountKeyPackageSlots {
        key_packages,
        returned_slots,
        complete,
        reached,
    }
}

/// The author's MLS KeyPackage with a legacy-profile account proof. Current
/// transport tag checks are skipped on purpose: deployed legacy publishers
/// predate them (MDK 0.8 publishes no `app_components` tag).
pub(crate) fn is_legacy_key_package_record(record: &RelayEventRecord) -> bool {
    let Ok(bytes) = BASE64_STANDARD.decode(record.event.content.as_bytes()) else {
        return false;
    };
    // `KeyPackage::new` annotates Legacy, so metadata decoding succeeds only
    // when the decoded account proof is legacy too.
    key_package_metadata(&KeyPackage::new(bytes)).is_ok_and(|metadata| {
        metadata.protocol_profile == ProtocolProfile::Legacy
            && metadata.credential_identity_hex == record.event.pubkey
    })
}

pub(crate) fn cached_key_package_from_entry(
    entry: UserDirectoryRecord,
) -> Result<Option<FetchedKeyPackage>, DirectoryError> {
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

#[cfg(any(test, feature = "test-support"))]
pub fn validated_cached_key_package(
    account_id_hex: &str,
    key_package: &DirectoryKeyPackage,
) -> Result<KeyPackage, DirectoryError> {
    validated_cached_key_package_with_ref(account_id_hex, key_package)
        .map(|(key_package, _)| key_package)
}

pub(crate) fn validated_cached_key_package_with_ref(
    account_id_hex: &str,
    key_package: &DirectoryKeyPackage,
) -> Result<(KeyPackage, String), DirectoryError> {
    let decoded = key_package_from_hex_with_optional_source(
        &key_package.key_package_hex,
        &key_package.key_package_event_id,
    )?;
    let metadata = key_package_metadata(&decoded)
        .map_err(|e| DirectoryError::InvalidKeyPackageEvent(e.to_string()))?;
    if metadata.protocol_profile != ProtocolProfile::Current {
        return Err(DirectoryError::InvalidKeyPackageEvent(
            "strict cutover rejects legacy KeyPackages for new joins".into(),
        ));
    }
    if metadata.credential_identity_hex != account_id_hex {
        return Err(DirectoryError::InvalidKeyPackageEvent(
            "cached KeyPackage credential identity does not match directory account".into(),
        ));
    }
    if !key_package.key_package_ref_hex.is_empty()
        && key_package.key_package_ref_hex != metadata.key_package_ref_hex
    {
        return Err(DirectoryError::InvalidKeyPackageEvent(
            "cached KeyPackage ref does not match decoded KeyPackageRef".into(),
        ));
    }
    Ok((
        decoded.with_protocol_profile(metadata.protocol_profile),
        metadata.key_package_ref_hex,
    ))
}

pub fn key_package_from_hex_with_optional_source(
    key_package_hex: &str,
    event_id_hex: &str,
) -> Result<KeyPackage, DirectoryError> {
    // After the strict cutover, unannotated local/directory cache records are
    // candidates only for the current profile. Mark them current before the
    // decoded proof/profile consistency check; legacy bytes then fail closed
    // and are replaced instead of being republished or selected for a join.
    let bytes = hex::decode(key_package_hex)?;
    if event_id_hex.is_empty() {
        return Ok(KeyPackage::new(bytes).with_protocol_profile(ProtocolProfile::Current));
    }
    Ok(
        KeyPackage::with_source_event_id(bytes, key_package_event_id_from_hex(event_id_hex)?)
            .with_protocol_profile(ProtocolProfile::Current),
    )
}

pub(crate) fn key_package_event_id_from_hex(
    event_id_hex: &str,
) -> Result<MessageId, DirectoryError> {
    let bytes = hex::decode(event_id_hex)?;
    if bytes.len() != 32 {
        return Err(DirectoryError::InvalidKeyPackageEvent(format!(
            "KeyPackage event id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(MessageId::new(bytes))
}

/// The selection's best KeyPackage or, when only future-dated slots hid it,
/// the cached one.
pub fn fresh_or_cached_key_package(
    account_id_hex: &str,
    selection: KeyPackageSelection,
    cached_entry: Option<UserDirectoryRecord>,
) -> Result<FetchedKeyPackage, DirectoryError> {
    if selection.value.is_empty()
        && selection.rejected_future
        && let Some(cached) = cached_entry
            .map(cached_key_package_from_entry)
            .transpose()?
            .flatten()
    {
        return Ok(cached);
    }
    Ok(selection
        .into_value_or_missing(account_id_hex)?
        .swap_remove(0))
}

pub fn key_package_from_record(
    record: RelayEventRecord,
) -> Result<FetchedKeyPackage, DirectoryError> {
    key_package_from_borrowed_record(&record)
}

pub(crate) fn key_package_from_borrowed_record(
    record: &RelayEventRecord,
) -> Result<FetchedKeyPackage, DirectoryError> {
    key_package_and_metadata_from_borrowed_record(record).map(|(fetched, _)| fetched)
}

fn key_package_and_metadata_from_borrowed_record(
    record: &RelayEventRecord,
) -> Result<(FetchedKeyPackage, KeyPackageMetadata), DirectoryError> {
    let event = &record.event;
    require_key_package_tag(event, "mls_protocol_version", |value| value == "1.0")?;
    let key_package_id = event
        .tag_value("d")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectoryError::InvalidKeyPackageEvent("missing d tag".into()))?
        .to_owned();
    let key_package_ref = event
        .tag_value("i")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectoryError::InvalidKeyPackageEvent("missing i tag".into()))?
        .to_owned();
    let key_package_bytes = BASE64_STANDARD
        .decode(event.content.as_bytes())
        .map_err(|e| {
            DirectoryError::InvalidKeyPackageEvent(format!("invalid base64 content: {e}"))
        })?;
    if key_package_bytes.is_empty() {
        return Err(DirectoryError::InvalidKeyPackageEvent(
            "empty key package content".into(),
        ));
    }
    // Strict cutover only permits relay-fetched KeyPackages for new joins to
    // use the current profile. Annotate the transport DTO before decoding its
    // proof/profile metadata; the raw-byte constructor defaults to Legacy for
    // backward-compatible callers and would otherwise misclassify every
    // freshly published current KeyPackage.
    let key_package = KeyPackage::with_source_event_id(
        key_package_bytes,
        key_package_event_id_from_hex(&event.id)?,
    )
    .with_protocol_profile(ProtocolProfile::Current);
    let metadata = key_package_metadata(&key_package)
        .map_err(|e| DirectoryError::InvalidKeyPackageEvent(e.to_string()))?;
    require_key_package_tag(event, "mls_ciphersuite", |value| {
        value == format!("0x{:04x}", metadata.ciphersuite)
    })?;
    require_multi_value_key_package_tag_matches(
        event,
        "mls_extensions",
        metadata.mls_extensions.iter().copied(),
    )?;
    require_multi_value_key_package_tag_matches(
        event,
        "mls_proposals",
        metadata.mls_proposals.iter().copied(),
    )?;
    require_multi_value_key_package_tag_matches(
        event,
        "app_components",
        metadata
            .app_components
            .iter()
            .copied()
            .filter(|id| *id >= PRIVATE_USE_APP_COMPONENT_ID_START),
    )?;
    let key_package = key_package.with_protocol_profile(metadata.protocol_profile);
    if metadata.credential_identity_hex != event.pubkey {
        return Err(DirectoryError::InvalidKeyPackageEvent(
            "transport author does not match KeyPackage credential identity".into(),
        ));
    }
    if metadata.key_package_ref_hex != key_package_ref {
        return Err(DirectoryError::InvalidKeyPackageEvent(
            "i tag does not match decoded KeyPackageRef".into(),
        ));
    }
    let mut source_relays = Vec::new();
    push_unique_strings(
        &mut source_relays,
        record
            .endpoints
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>(),
    );
    Ok((
        FetchedKeyPackage {
            account_id_hex: event.pubkey.clone(),
            key_package,
            key_package_id,
            key_package_ref_hex: metadata.key_package_ref_hex.clone(),
            key_package_event_id: event.id.clone(),
            created_at: event.created_at,
            source_relays,
            relay_lists: AccountRelayListStatus::empty(),
        },
        metadata,
    ))
}

/// Per spec/transports/nostr.md, each KeyPackage id-list tag is exactly one
/// tag. A consumer MUST reject an event that repeats an id-list tag name rather
/// than silently reading the first occurrence (two consumers could otherwise
/// pick different occurrences and disagree on advertised capabilities).
pub(crate) fn reject_duplicate_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
) -> Result<(), DirectoryError> {
    let count = event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .count();
    if count > 1 {
        return Err(DirectoryError::InvalidKeyPackageEvent(format!(
            "duplicate {name} tag"
        )));
    }
    Ok(())
}

pub fn require_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
) -> Result<(), DirectoryError> {
    reject_duplicate_key_package_tag(event, name)?;
    match event.tag_value(name) {
        Some(value) if predicate(value) => Ok(()),
        // Never echo the tag value: it is attacker-controlled kind:30443 event
        // content, and this error's Display reaches tracing at upper layers.
        Some(_) => Err(DirectoryError::InvalidKeyPackageEvent(format!(
            "invalid {name} tag"
        ))),
        None => Err(DirectoryError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        ))),
    }
}

pub fn require_multi_value_key_package_tag_matches(
    event: &NostrTransportEvent,
    name: &str,
    expected_ids: impl IntoIterator<Item = u16>,
) -> Result<(), DirectoryError> {
    reject_duplicate_key_package_tag(event, name)?;
    let Some(tag) = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
    else {
        return Err(DirectoryError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        )));
    };
    let values = tag.iter().skip(1).cloned().collect::<Vec<_>>();
    let actual = values.iter().cloned().collect::<BTreeSet<_>>();
    let expected = expected_ids
        .into_iter()
        .map(|id| format!("0x{id:04x}"))
        .collect::<BTreeSet<_>>();
    if values.len() != actual.len() || actual != expected {
        return Err(DirectoryError::InvalidKeyPackageEvent(format!(
            "{name} tag does not exactly match decoded KeyPackage metadata"
        )));
    }
    Ok(())
}

pub(crate) fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}
