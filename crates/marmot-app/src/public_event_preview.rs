//! Account-scoped public event preview persistence and bounded native refresh.
//!
//! The cache keeps only signature-verified events that exactly match a canonical
//! reference, authenticated NIP-09 deletion evidence and the ordering fences that
//! deletion leaves behind. Relay I/O lives in `relay_plane::public_event_query`;
//! nothing here holds a database or account guard across an await.
//!
//! Deletion evidence model. A tombstone stores the complete signed kind-5
//! request. For an event-ID target it also stores a compact proof of the removed
//! target, `(event_id, pubkey, signature)`, whose signature is re-verified over
//! the ID whenever the tombstone is used: that authenticates authorship. The
//! removed target's raw content is never retained. Its kind, coordinate
//! (cohort) and selection rank cannot be re-derived from the proof; they are
//! admission provenance recorded when the full target was verified locally.
//! Every retained tombstone field that carries authority (cache and cohort key,
//! target kind, rank time and ID, selection-fence flag, compact proof,
//! projection version, receipt time and the signed deletion JSON) is bound by a
//! domain-separated HMAC-SHA256 whose key is derived with HKDF from the
//! account's private SQLCipher key. The key lives only in memory, zeroized on
//! drop, and is never stored or exposed. The MAC is checked in constant time
//! before any unsigned field is used, so moving a tombstone to another cohort or
//! changing its rank, kind, fence flag, proof or version fails closed instead of
//! suppressing unrelated content.
//!
//! Row MACs cannot prove absence: a relocated, renamed or deleted row would
//! simply not be found under its original key. Every SQL lookup by `cache_key`
//! or `cohort_key` therefore relies on an authenticated tombstone inventory: one
//! singleton HMAC (same key, separate domain) over the count and the sorted
//! `(cache_key, cohort_key, provenance_mac)` of every tombstone. Each read or
//! admission verifies it once, in the same locked connection or immediate
//! transaction, before any index is trusted to include or exclude evidence;
//! every legitimate tombstone write, eviction or migration rewrites it in the
//! same transaction. A missing, stale or forged inventory fails closed. The
//! inventory scan reads only a covering index of at most 1,024 rows of bounded
//! keys (each at most 1,103 bytes), about 2.3 MiB in the worst case and never the
//! signed payloads; a batch read verifies it once. Rolling back the whole
//! encrypted file to an earlier consistent state is outside this check.
//!
//! Only a first `d` value of at most 1,024 bytes forms a coordinate. A valid
//! event with a longer identifier remains cacheable by exact ID as its own
//! cohort, like an immutable event, so it never creates a large address cohort;
//! only `e` deletions can name it.
//!
//! Byte accounting counts every variable retained field (keys, signed JSON,
//! proof, rank ID, MAC and their index copies) plus a fixed per-row overhead.
//! Trimming recomputes it from stored lengths and never trusts a smaller
//! stored `bytes` value.
//!
//! Eviction removes a whole cohort (a coordinate with its event-ID aliases,
//! selection and tombstones, or one immutable event with its tombstone) at once,
//! both under the global record/byte budget and when one coordinate collects
//! more than 64 event-ID tombstones. Evicting a cohort completely ends local
//! deletion knowledge for it: a later admission starts that cohort from scratch,
//! exactly like a cold cache, and never sees a newer retained member without the
//! evidence that fenced older ones.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use cgka_traits::TransportEndpoint;
use cgka_traits::storage::StorageError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use nostr::event::Event;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use storage_sqlite::{
    CloseableConnection, SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher,
};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::relay_plane::{
    PUBLIC_EVENT_QUERY_MAX_RELAYS, PublicEventQueryBudget, PublicEventQueryFilter,
    PublicEventTrafficLimits, PublicEventTrafficMeter,
};
use crate::sqlcipher::SqlcipherDatabaseKind;
use crate::{AppError, MarmotApp, UserProfileMetadata};
use marmot_account::AccountSummary;
use nostr::nips::nip19::{FromBech32, Nip19};

/// Version of [`PublicEventPreview`] and [`PublicEventDeletion`] projections.
/// Stored rows carrying any other version fail closed instead of being rewritten.
pub const PUBLIC_EVENT_PROJECTION_VERSION: u32 = 1;
/// Maximum references in one synchronous cached batch read.
pub const MAX_PUBLIC_EVENT_REFERENCES: usize = 16;
/// Maximum UTF-8 bytes of one reference string.
pub const MAX_PUBLIC_EVENT_REFERENCE_BYTES: usize = 5000;

/// An exact event ID with optional lookup hints, or a complete naddr coordinate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicEventReference {
    pub event_id_hex: Option<String>,
    pub author_pubkey_hex: Option<String>,
    pub kind: Option<u32>,
    pub identifier: Option<String>,
}

/// Canonical cache identity. Relay hints, nevent author/kind hints and account
/// identity never take part in it; the account is the cache's own scope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PublicEventCacheKey {
    /// `note`, `nevent` or 64-character hexadecimal event ID.
    EventId { event_id_hex: String },
    /// Complete `naddr` coordinate. Replaceable kinds use an empty identifier.
    Coordinate {
        kind: u32,
        author_pubkey_hex: String,
        identifier: String,
    },
}

/// A selected signed event; callers shape its contents for their own presentation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicEventPreview {
    pub event_json: String,
    pub received_at: u64,
    pub refresh_recommended: bool,
    pub author_profile: Option<UserProfileMetadata>,
    pub projection_version: u32,
}

/// Authenticated NIP-09 evidence that the referenced event (or every cached
/// version of a coordinate up to the request time) was deleted by its author.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicEventDeletion {
    pub deletion_event_json: String,
    pub received_at: u64,
    pub projection_version: u32,
}

/// Local state for one reference. `Missing` is never durable negative truth and
/// `Busy` is retryable, never a miss: account lifecycle work holds the account,
/// or the account cache this request started with was removed, wiped,
/// reimported or closed meanwhile (a retry reads the current incarnation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicEventCacheResult {
    Present(Box<PublicEventPreview>),
    AuthoritativeDeleted(PublicEventDeletion),
    Missing,
    Busy,
}

/// One result per requested reference, in request order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicEventCacheRead {
    pub key: PublicEventCacheKey,
    pub result: PublicEventCacheResult,
}

impl PublicEventCacheResult {
    #[cfg(test)]
    fn into_present(self) -> Option<PublicEventPreview> {
        match self {
            Self::Present(preview) => Some(*preview),
            _ => None,
        }
    }
}

impl PublicEventCacheKey {
    pub(crate) fn storage_key(&self) -> String {
        match self {
            Self::EventId { event_id_hex } => format!("event:{event_id_hex}"),
            Self::Coordinate {
                kind,
                author_pubkey_hex,
                identifier,
            } => coordinate_storage_key(*kind, author_pubkey_hex, identifier),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PublicEventCache {
    conn: Arc<CloseableConnection>,
    provenance: Arc<ProvenanceKey>,
    future_skew: Duration,
    refresh: Arc<StdMutex<RefreshState>>,
}

/// Runtime-only HMAC key for tombstone provenance. Derived from the private
/// SQLCipher key, zeroized on drop, never persisted, logged or exposed.
struct ProvenanceKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for ProvenanceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvenanceKey(<redacted>)")
    }
}

const PROVENANCE_HKDF_SALT: &[u8] = b"marmot-app/public-event-cache/v1";
const PROVENANCE_HKDF_INFO: &[u8] = b"marmot-app/public-event-tombstone-provenance/hmac-sha256";
const PROVENANCE_MAC_DOMAIN: &[u8] = b"marmot-app/public-event-tombstone/v1";
const INVENTORY_MAC_DOMAIN: &[u8] = b"marmot-app/public-event-tombstone-inventory/v1";
const PROVENANCE_MAC_BYTES: usize = 32;

/// Length-prefixed MAC input, so adjacent fields can never be confused.
fn put_mac_field(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(bytes);
}

impl ProvenanceKey {
    fn derive(key: &SqlCipherKey) -> Result<Self, AppError> {
        let hkdf = Hkdf::<Sha256>::new(Some(PROVENANCE_HKDF_SALT), key.as_secret_str().as_bytes());
        let mut output = Zeroizing::new([0_u8; 32]);
        hkdf.expand(PROVENANCE_HKDF_INFO, output.as_mut())
            .map_err(|_| AppError::SqlcipherKeyDerivation("HKDF output length rejected".into()))?;
        Ok(Self(output))
    }

    fn keyed(&self) -> Result<Hmac<Sha256>, AppError> {
        <Hmac<Sha256> as Mac>::new_from_slice(&self.0[..])
            .map_err(|_| AppError::SqlcipherKeyDerivation("HMAC key rejected".into()))
    }

    fn mac(&self, record: &TombstoneRecord) -> Result<Hmac<Sha256>, AppError> {
        let mut mac = self.keyed()?;
        mac.update(&record.mac_input());
        Ok(mac)
    }

    fn tag(&self, record: &TombstoneRecord) -> Result<Vec<u8>, AppError> {
        Ok(self.mac(record)?.finalize().into_bytes().to_vec())
    }

    /// Constant-time comparison of the stored tag with the recomputed one.
    fn verify(&self, record: &TombstoneRecord, tag: &[u8]) -> Result<bool, AppError> {
        Ok(tag.len() == PROVENANCE_MAC_BYTES && self.mac(record)?.verify_slice(tag).is_ok())
    }
}

const MAX_EVENT_BYTES: usize = 256 * 1024;
// Sixteen candidates of at most 256 KiB bound one admission batch to 4 MiB.
const MAX_CANDIDATES: usize = 16;
const MAX_ENTRIES: i64 = 1024;
const MAX_TOTAL_BYTES: i64 = 32 * 1024 * 1024;
/// Event-ID tombstones one coordinate cohort may retain. One more evicts the
/// whole cohort, never only its oldest evidence.
const MAX_COHORT_TOMBSTONES: i64 = 64;
const ADDRESS_REFRESH_SECONDS: u64 = 15 * 60;
/// Schema 4 binds tombstone provenance with per-row HMACs and the tombstone set
/// with an authenticated inventory. The unreleased schema 2 (unauthenticated
/// provenance) and schema 3 (no authenticated inventory) fail closed.
const SCHEMA_VERSION: i64 = 4;
/// Largest first `d` value that forms a coordinate (cache key or cohort).
const MAX_COORDINATE_IDENTIFIER_BYTES: usize = 1024;
/// Largest storage key: `address:65535:<64 hex>:` plus a maximal identifier.
/// The tombstone table's CHECK constraints use the same literal.
const MAX_STORAGE_KEY_BYTES: usize = 79 + MAX_COORDINATE_IDENTIFIER_BYTES;
/// Fixed logical bytes charged per retained row (integers, versions, flags and
/// row headers) on top of its variable fields.
const ROW_OVERHEAD_BYTES: usize = 64;
/// Logical bytes of the inventory singleton.
const INVENTORY_BYTES: i64 = (ROW_OVERHEAD_BYTES + PROVENANCE_MAC_BYTES) as i64;
/// Largest logical size of one tombstone; the table's CHECK uses the literal.
const MAX_TOMBSTONE_BYTES: usize = 270_336;
/// Logical bytes of a stored preview row: every variable field, keys counted
/// with their index copies, computed from stored lengths (record headers,
/// never payload contents).
const PREVIEW_LOGICAL_BYTES_SQL: &str =
    "(64 + 3 * octet_length(cache_key) + octet_length(event_json)
    + 2 * coalesce(octet_length(rank_event_id), 0) + 2 * coalesce(octet_length(cohort_key), 0))";
/// The inventory scan; served from the covering inventory index alone.
const INVENTORY_SCAN_SQL: &str = "SELECT cache_key, cohort_key, provenance_mac
    FROM public_event_tombstones ORDER BY cache_key LIMIT ?1";
/// Logical bytes of a stored tombstone row; mirrors [`tombstone_logical_bytes`].
const TOMBSTONE_LOGICAL_BYTES_SQL: &str = "(64 + 4 * octet_length(cache_key)
    + 3 * octet_length(cohort_key) + octet_length(deletion_json)
    + coalesce(octet_length(proof_event_id), 0) + coalesce(octet_length(proof_pubkey), 0)
    + coalesce(octet_length(proof_sig), 0) + octet_length(rank_event_id)
    + 2 * octet_length(provenance_mac))";
const KIND_METADATA: u16 = 0;
const KIND_DELETION: u16 = 5;
const MAX_HINT_RELAYS: usize = 2;
const RESOLVE_DEADLINE: Duration = Duration::from_secs(10);
const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_INFLIGHT_REFRESHES: usize = 16;
const MAX_COOLDOWN_ENTRIES: usize = 256;
/// Request-wide received traffic across every relay and phase: sixteen decoded
/// `EVENT` envelopes, 4 MiB of raw wire bytes (a conservative budget that also
/// charges TLS/HTTP handshakes, frame headers and fragments), plus a bounded
/// count of other relay messages and control frames.
const REQUEST_TRAFFIC: PublicEventTrafficLimits = PublicEventTrafficLimits {
    max_items: 16,
    max_bytes: 4 * 1024 * 1024,
    max_messages: 64,
};
// The phase budgets reserve request capacity for the target phase and for the
// deletion/metadata phase.
const TARGET_PHASE_BUDGET: PublicEventQueryBudget = PublicEventQueryBudget {
    max_items: 8,
    max_bytes: 2 * 1024 * 1024,
};
const EVIDENCE_PHASE_BUDGET: PublicEventQueryBudget = PublicEventQueryBudget {
    max_items: 8,
    max_bytes: 2 * 1024 * 1024,
};

const SCHEMA_V1: &str = "CREATE TABLE public_event_previews (
    cache_key TEXT PRIMARY KEY NOT NULL,
    event_json TEXT NOT NULL,
    received_at INTEGER NOT NULL CHECK (received_at >= 0),
    touched_at INTEGER NOT NULL CHECK (touched_at >= 0),
    bytes INTEGER NOT NULL CHECK (bytes > 0 AND bytes <= 262144)
);
CREATE INDEX public_event_previews_touched ON public_event_previews(touched_at, cache_key);";

/// Schema 1 -> 4. Schema 1 held only raw signed events, which are re-verified
/// row by row; no unauthenticated provenance exists to carry forward. The
/// empty tombstone inventory is authenticated by the migration itself.
const SCHEMA_V4_MIGRATION: &str = "ALTER TABLE public_event_previews
    ADD COLUMN projection_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE public_event_previews ADD COLUMN rank_created_at INTEGER;
ALTER TABLE public_event_previews ADD COLUMN rank_event_id TEXT;
ALTER TABLE public_event_previews ADD COLUMN cohort_key TEXT;
CREATE INDEX public_event_previews_rank ON public_event_previews(rank_event_id);
CREATE INDEX public_event_previews_cohort ON public_event_previews(cohort_key);
CREATE TABLE public_event_tombstones (
    cache_key TEXT PRIMARY KEY NOT NULL
        CHECK ((substr(cache_key, 1, 6) = 'event:' OR substr(cache_key, 1, 8) = 'address:')
            AND length(CAST(cache_key AS BLOB)) <= 1103),
    cohort_key TEXT NOT NULL CHECK (length(CAST(cohort_key AS BLOB)) <= 1103),
    deletion_json TEXT NOT NULL,
    received_at INTEGER NOT NULL CHECK (received_at >= 0),
    touched_at INTEGER NOT NULL CHECK (touched_at >= 0),
    bytes INTEGER NOT NULL CHECK (bytes > 0 AND bytes <= 270336),
    projection_version INTEGER NOT NULL,
    proof_event_id TEXT,
    proof_pubkey TEXT,
    proof_sig TEXT,
    target_kind INTEGER NOT NULL CHECK (target_kind >= 0 AND target_kind <= 65535),
    rank_created_at INTEGER NOT NULL,
    rank_event_id TEXT NOT NULL,
    fences_selection INTEGER NOT NULL CHECK (fences_selection IN (0, 1)),
    provenance_mac BLOB NOT NULL CHECK (length(provenance_mac) = 32),
    CHECK ((proof_event_id IS NULL) = (proof_pubkey IS NULL)
        AND (proof_pubkey IS NULL) = (proof_sig IS NULL))
);
CREATE INDEX public_event_tombstones_touched ON public_event_tombstones(touched_at, cache_key);
CREATE INDEX public_event_tombstones_cohort ON public_event_tombstones(cohort_key);
CREATE INDEX public_event_tombstones_inventory
    ON public_event_tombstones(cache_key, cohort_key, provenance_mac);
CREATE TABLE public_event_tombstone_inventory (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    tombstone_count INTEGER NOT NULL CHECK (tombstone_count >= 0),
    inventory_mac BLOB NOT NULL CHECK (length(inventory_mac) = 32)
);";

impl PublicEventReference {
    /// Decode shared human-facing references; relay hints never enter storage identity.
    pub fn parse(reference: &str) -> Result<Self, AppError> {
        Self::parse_with_hints(reference).map(|(reference, _)| reference)
    }

    /// Validate a whole batch before any storage is opened.
    pub(crate) fn parse_batch(references: &[String]) -> Result<Vec<Self>, AppError> {
        if references.len() > MAX_PUBLIC_EVENT_REFERENCES {
            return Err(budget_error());
        }
        references
            .iter()
            .map(|reference| Self::parse(reference))
            .collect()
    }

    /// Like [`Self::parse`], also returning the reference's relay hints. Hints are
    /// untrusted, ephemeral query inputs and are never persisted.
    pub(crate) fn parse_with_hints(reference: &str) -> Result<(Self, Vec<String>), AppError> {
        let reference = reference.trim();
        if reference.len() > MAX_PUBLIC_EVENT_REFERENCE_BYTES {
            return Err(invalid_reference());
        }
        let reference = if reference
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("nostr:"))
        {
            &reference[6..]
        } else {
            reference
        };
        let (result, hints) =
            if reference.len() == 64 && reference.bytes().all(|b| b.is_ascii_hexdigit()) {
                (
                    Self {
                        event_id_hex: Some(reference.to_ascii_lowercase()),
                        author_pubkey_hex: None,
                        kind: None,
                        identifier: None,
                    },
                    Vec::new(),
                )
            } else {
                let lower = reference.to_ascii_lowercase();
                if !(lower.starts_with("note1")
                    || lower.starts_with("nevent1")
                    || lower.starts_with("naddr1"))
                {
                    return Err(invalid_reference());
                }
                match Nip19::from_bech32(reference).map_err(|_| invalid_reference())? {
                    Nip19::EventId(id) => (
                        Self {
                            event_id_hex: Some(id.to_hex()),
                            author_pubkey_hex: None,
                            kind: None,
                            identifier: None,
                        },
                        Vec::new(),
                    ),
                    Nip19::Event(event) => {
                        let hints = event
                            .relays
                            .iter()
                            .take(PUBLIC_EVENT_QUERY_MAX_RELAYS)
                            .map(ToString::to_string)
                            .collect();
                        (
                            Self {
                                event_id_hex: Some(event.event_id.to_hex()),
                                author_pubkey_hex: event.author.map(|key| key.to_hex()),
                                kind: event.kind.map(|kind| u32::from(kind.as_u16())),
                                identifier: None,
                            },
                            hints,
                        )
                    }
                    Nip19::Coordinate(address) => {
                        let hints = address
                            .relays
                            .iter()
                            .take(PUBLIC_EVENT_QUERY_MAX_RELAYS)
                            .map(ToString::to_string)
                            .collect();
                        (
                            Self {
                                event_id_hex: None,
                                author_pubkey_hex: Some(address.coordinate.public_key.to_hex()),
                                kind: Some(u32::from(address.coordinate.kind.as_u16())),
                                identifier: Some(address.coordinate.identifier),
                            },
                            hints,
                        )
                    }
                    _ => return Err(invalid_reference()),
                }
            };
        result.cache_key()?;
        Ok((result, hints))
    }

    /// The canonical key: the exact event ID, or the complete coordinate.
    pub fn cache_key(&self) -> Result<PublicEventCacheKey, AppError> {
        if self.kind.is_some_and(|kind| kind > u16::MAX.into())
            || self
                .author_pubkey_hex
                .as_deref()
                .is_some_and(|key| !is_hex64(key))
        {
            return Err(invalid_reference());
        }
        if let Some(id) = &self.event_id_hex {
            if !is_hex64(id) || self.identifier.is_some() {
                return Err(invalid_reference());
            }
            return Ok(PublicEventCacheKey::EventId {
                event_id_hex: id.to_ascii_lowercase(),
            });
        }
        let (Some(author), Some(kind), Some(identifier)) =
            (&self.author_pubkey_hex, self.kind, &self.identifier)
        else {
            return Err(invalid_reference());
        };
        if identifier.len() > MAX_COORDINATE_IDENTIFIER_BYTES
            || !(is_addressable(kind) || (is_replaceable(kind) && identifier.is_empty()))
        {
            return Err(invalid_reference());
        }
        Ok(PublicEventCacheKey::Coordinate {
            kind,
            author_pubkey_hex: author.to_ascii_lowercase(),
            identifier: identifier.clone(),
        })
    }

    fn key(&self) -> Result<String, AppError> {
        self.cache_key().map(|key| key.storage_key())
    }

    fn matches(&self, event: &Event) -> bool {
        if !supported_target(event) {
            return false;
        }
        if let Some(id) = &self.event_id_hex {
            // Optional nevent metadata helps locate the immutable signed ID;
            // it must not become a conflicting identity or a second cache key.
            return id.eq_ignore_ascii_case(&event.id.to_hex());
        }
        if self
            .author_pubkey_hex
            .as_ref()
            .is_some_and(|key| !key.eq_ignore_ascii_case(&event.pubkey.to_hex()))
            || self.kind.is_some_and(|kind| kind != event_kind(event))
        {
            return false;
        }
        if !is_addressable(event_kind(event)) {
            return self.identifier.as_deref() == Some("");
        }
        self.identifier.as_deref() == Some(first_d_tag(event))
    }
}

fn invalid_reference() -> AppError {
    StorageError::Serialization("invalid public event reference".into()).into()
}

fn budget_error() -> AppError {
    StorageError::Serialization("public event batch exceeds its budget".into()).into()
}

fn unsupported_projection() -> AppError {
    StorageError::Backend("unsupported public event projection version".into()).into()
}

fn corrupt_evidence() -> AppError {
    StorageError::Backend("public event deletion evidence failed verification".into()).into()
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn normalized_hex64(value: &str) -> Option<String> {
    is_hex64(value).then(|| value.to_ascii_lowercase())
}

fn is_addressable(kind: u32) -> bool {
    (30_000..40_000).contains(&kind)
}

fn is_replaceable(kind: u32) -> bool {
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

fn event_kind(event: &Event) -> u32 {
    u32::from(event.kind.as_u16())
}

/// The first `d` tag decides the coordinate, even when it carries no value.
fn first_d_tag(event: &Event) -> &str {
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().is_some_and(|name| name == "d"))
        .and_then(|tag| tag.as_slice().get(1))
        .map(String::as_str)
        .unwrap_or("")
}

fn coordinate_storage_key(kind: u32, author_hex: &str, identifier: &str) -> String {
    format!("address:{kind}:{author_hex}:{identifier}")
}

/// The coordinate a verified replaceable or addressable event belongs to. An
/// identifier above [`MAX_COORDINATE_IDENTIFIER_BYTES`] forms no coordinate:
/// such an event stays an exact-ID entry and never a large address cohort.
fn event_coordinate_key(event: &Event) -> Option<String> {
    let kind = event_kind(event);
    let identifier = if is_addressable(kind) {
        first_d_tag(event)
    } else if is_replaceable(kind) {
        ""
    } else {
        return None;
    };
    if identifier.len() > MAX_COORDINATE_IDENTIFIER_BYTES {
        return None;
    }
    Some(coordinate_storage_key(
        kind,
        &event.pubkey.to_hex(),
        identifier,
    ))
}

/// Kind and author of a canonical coordinate storage key.
fn parse_coordinate_key(coordinate_key: &str) -> Option<(u32, &str)> {
    let mut parts = coordinate_key.strip_prefix("address:")?.splitn(3, ':');
    let kind = parts.next()?;
    if kind.is_empty() || !kind.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let kind: u32 = kind.parse().ok()?;
    let author = parts.next()?;
    let identifier = parts.next()?;
    let canonical_author = author.len() == 64
        && author
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (canonical_author
        && kind <= u32::from(u16::MAX)
        && (is_addressable(kind) || (is_replaceable(kind) && identifier.is_empty())))
    .then_some((kind, author))
}

/// The cohort an event belongs to: its coordinate, or its own event key.
fn event_cohort_key(event: &Event) -> String {
    event_coordinate_key(event).unwrap_or_else(|| format!("event:{}", event.id.to_hex()))
}

/// Canonical coordinate key and author for a NIP-01 `a` tag value. Kinds that
/// are neither replaceable nor addressable (including kind 5) never qualify.
fn parse_a_tag(value: &str) -> Option<(String, String)> {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next()?;
    if kind.is_empty() || !kind.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let kind: u32 = kind.parse().ok()?;
    let author = normalized_hex64(parts.next()?)?;
    let identifier = parts.next()?;
    if kind > u32::from(u16::MAX)
        || identifier.len() > MAX_COORDINATE_IDENTIFIER_BYTES
        || !(is_addressable(kind) || (is_replaceable(kind) && identifier.is_empty()))
    {
        return None;
    }
    Some((coordinate_storage_key(kind, &author, identifier), author))
}

fn deletion_targets_event(deletion: &Event, event_id_hex: &str) -> bool {
    deletion.tags.iter().any(|tag| {
        let values = tag.as_slice();
        values.first().is_some_and(|name| name == "e")
            && values
                .get(1)
                .is_some_and(|value| value.eq_ignore_ascii_case(event_id_hex))
    })
}

fn deletion_targets_coordinate(deletion: &Event, coordinate_key: &str) -> bool {
    deletion.tags.iter().any(|tag| {
        let values = tag.as_slice();
        values.first().is_some_and(|name| name == "a")
            && values
                .get(1)
                .and_then(|value| parse_a_tag(value))
                .is_some_and(|(coordinate, _)| coordinate == coordinate_key)
    })
}

/// BIP-340 verification of a compact `(id, pubkey, signature)` authorship proof.
fn verify_id_signature(id_hex: &str, pubkey_hex: &str, signature_hex: &str) -> bool {
    use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};

    let (mut id, mut public_key, mut signature) = ([0u8; 32], [0u8; 32], [0u8; 64]);
    if hex::decode_to_slice(id_hex, &mut id).is_err()
        || hex::decode_to_slice(pubkey_hex, &mut public_key).is_err()
        || hex::decode_to_slice(signature_hex, &mut signature).is_err()
    {
        return false;
    }
    let (Ok(public_key), Ok(signature)) = (
        XOnlyPublicKey::from_slice(&public_key),
        Signature::from_slice(&signature),
    ) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &id, &public_key)
        .is_ok()
}

fn parse_verified(json: &str) -> Option<Event> {
    if json.len() > MAX_EVENT_BYTES {
        return None;
    }
    let event = Event::from_json(json).ok()?;
    event.verify().is_ok().then_some(event)
}

/// Every admitted target keeps its full deletion semantics within the same coordinate budget.
fn supported_target(event: &Event) -> bool {
    !is_addressable(event_kind(event)) || first_d_tag(event).len() <= 1024
}

fn verified_event(json: &str, reference: &PublicEventReference) -> Option<Event> {
    parse_verified(json).filter(|event| reference.matches(event))
}

type Rank = (u64, String);

fn rank(event: &Event) -> Rank {
    (event.created_at.as_secs(), event.id.to_hex())
}

/// Newest creation time wins; a same-second tie selects the lowest event ID.
fn beats(candidate: &Rank, current: &Rank) -> bool {
    candidate.0 > current.0 || (candidate.0 == current.0 && candidate.1 < current.1)
}

fn i64_secs(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

struct StoredPreview {
    preview: PublicEventPreview,
    event: Event,
}

/// Every retained tombstone field that carries authority; exactly the input of
/// the provenance MAC. `touched_at` (LRU only) and `bytes` (derived) are not.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TombstoneRecord {
    cache_key: String,
    cohort_key: String,
    deletion_json: String,
    received_at: i64,
    projection_version: i64,
    /// Compact original `(event_id, pubkey, signature)` of an event-ID target.
    proof: Option<(String, String, String)>,
    target_kind: i64,
    rank_created_at: i64,
    rank_event_id: String,
    fences_selection: bool,
}

impl TombstoneRecord {
    /// Unambiguous, domain-separated encoding: every field is length-prefixed.
    fn mac_input(&self) -> Vec<u8> {
        fn put(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(self.deletion_json.len() + 512);
        put(&mut out, PROVENANCE_MAC_DOMAIN);
        put(&mut out, self.cache_key.as_bytes());
        put(&mut out, self.cohort_key.as_bytes());
        put(&mut out, self.deletion_json.as_bytes());
        put(&mut out, &self.received_at.to_be_bytes());
        put(&mut out, &self.projection_version.to_be_bytes());
        match &self.proof {
            Some((id, pubkey, signature)) => {
                put(&mut out, &[1]);
                put(&mut out, id.as_bytes());
                put(&mut out, pubkey.as_bytes());
                put(&mut out, signature.as_bytes());
            }
            None => put(&mut out, &[0]),
        }
        put(&mut out, &self.target_kind.to_be_bytes());
        put(&mut out, &self.rank_created_at.to_be_bytes());
        put(&mut out, self.rank_event_id.as_bytes());
        put(&mut out, &[u8::from(self.fences_selection)]);
        out
    }

    fn proof_bytes(&self) -> usize {
        self.proof
            .as_ref()
            .map_or(0, |(id, pubkey, sig)| id.len() + pubkey.len() + sig.len())
    }
}

/// Logical bytes of a tombstone: every variable retained field (keys with
/// their index copies, signed JSON, proof, rank ID, MAC with its inventory
/// index copy) plus a fixed row overhead. Mirrors
/// [`TOMBSTONE_LOGICAL_BYTES_SQL`].
fn tombstone_logical_bytes(record: &TombstoneRecord, mac_bytes: usize) -> usize {
    ROW_OVERHEAD_BYTES
        + 4 * record.cache_key.len()
        + 3 * record.cohort_key.len()
        + record.deletion_json.len()
        + record.proof_bytes()
        + record.rank_event_id.len()
        + 2 * mac_bytes
}

/// A stored row as read, before authentication.
struct StoredTombstone {
    record: TombstoneRecord,
    /// The proof columns or the fence flag violated their own shape.
    malformed: bool,
    mac: Vec<u8>,
}

const TOMBSTONE_COLUMNS: &str = "cache_key, cohort_key, deletion_json, received_at,
    projection_version, proof_event_id, proof_pubkey, proof_sig, target_kind,
    rank_created_at, rank_event_id, fences_selection, provenance_mac";

fn stored_tombstone(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredTombstone> {
    let proof_columns: (Option<String>, Option<String>, Option<String>) =
        (row.get(5)?, row.get(6)?, row.get(7)?);
    let fences: i64 = row.get(11)?;
    let (proof, proof_malformed) = match proof_columns {
        (Some(id), Some(pubkey), Some(sig)) => (Some((id, pubkey, sig)), false),
        (None, None, None) => (None, false),
        _ => (None, true),
    };
    Ok(StoredTombstone {
        record: TombstoneRecord {
            cache_key: row.get(0)?,
            cohort_key: row.get(1)?,
            deletion_json: row.get(2)?,
            received_at: row.get(3)?,
            projection_version: row.get(4)?,
            proof,
            target_kind: row.get(8)?,
            rank_created_at: row.get(9)?,
            rank_event_id: row.get(10)?,
            fences_selection: fences == 1,
        },
        malformed: proof_malformed || !(fences == 0 || fences == 1),
        mac: row.get(12)?,
    })
}

/// A tombstone whose provenance MAC and structure were checked.
struct Tombstone {
    record: TombstoneRecord,
    deletion: Event,
    received_at: u64,
    rank_created_at: u64,
}

impl Tombstone {
    fn projection(&self) -> PublicEventDeletion {
        PublicEventDeletion {
            deletion_event_json: self.deletion.as_json(),
            received_at: self.received_at,
            projection_version: PUBLIC_EVENT_PROJECTION_VERSION,
        }
    }

    fn cache_key(&self) -> &str {
        &self.record.cache_key
    }

    fn rank(&self) -> Rank {
        (self.rank_created_at, self.record.rank_event_id.clone())
    }

    /// Re-verify the signed deletion and the compact authorship proof before
    /// this tombstone is used as authority.
    fn authenticate(self) -> Result<Self, AppError> {
        let proof_ok = self
            .record
            .proof
            .as_ref()
            .is_none_or(|(id, pubkey, sig)| verify_id_signature(id, pubkey, sig));
        if self.deletion.verify().is_err() || !proof_ok {
            return Err(corrupt_evidence());
        }
        Ok(self)
    }
}

/// The best-ranked tombstone: newest time, then lowest event ID.
fn best_ranked(tombstones: impl IntoIterator<Item = Tombstone>) -> Option<Tombstone> {
    let mut best: Option<Tombstone> = None;
    for tombstone in tombstones {
        if best
            .as_ref()
            .is_none_or(|current| beats(&tombstone.rank(), &current.rank()))
        {
            best = Some(tombstone);
        }
    }
    best
}

#[derive(Debug, Default)]
struct RefreshState {
    inflight: HashMap<String, watch::Receiver<()>>,
    cooldown_until: HashMap<String, Instant>,
}

/// In-memory refresh admission for one key; nothing here is durable.
pub(crate) enum RefreshAdmission {
    Lead(RefreshLease),
    Coalesced(watch::Receiver<()>),
    CoolingDown,
    Saturated,
}

/// Exclusive refresh ownership for one key. Dropping it, including on caller
/// cancellation, wakes coalesced waiters; an attempted refresh starts the
/// retry cooldown.
pub(crate) struct RefreshLease {
    state: Arc<StdMutex<RefreshState>>,
    key: String,
    attempted: bool,
    _done: watch::Sender<()>,
}

impl RefreshLease {
    pub(crate) fn mark_attempted(&mut self) {
        self.attempted = true;
    }
}

impl Drop for RefreshLease {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.inflight.remove(&self.key);
        if self.attempted {
            let now = Instant::now();
            state.cooldown_until.retain(|_, until| *until > now);
            if state.cooldown_until.len() >= MAX_COOLDOWN_ENTRIES
                && let Some(oldest) = state
                    .cooldown_until
                    .iter()
                    .min_by_key(|(_, until)| **until)
                    .map(|(key, _)| key.clone())
            {
                state.cooldown_until.remove(&oldest);
            }
            state
                .cooldown_until
                .insert(self.key.clone(), now + REFRESH_COOLDOWN);
        }
    }
}

impl PublicEventCache {
    pub(crate) fn open(
        path: &Path,
        key: &SqlCipherKey,
        future_skew: Duration,
    ) -> Result<Self, AppError> {
        let provenance = Arc::new(ProvenanceKey::derive(key)?);
        fs_private::ensure_private_db_files(path)?;
        let mut conn = Connection::open(path)?;
        open_hardened_sqlcipher(&conn, key, SqlCipherHardening::live_cache())?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let migrated = version != SCHEMA_VERSION;
        if version == 0 {
            tx.execute_batch(SCHEMA_V1)?;
            version = 1;
        }
        if version == 1 {
            Self::migrate_v1_to_v4(&tx, &provenance)?;
            version = SCHEMA_VERSION;
        }
        // Unknown, newer, or the unreleased schemas 2 and 3 fail closed; they
        // are never recreated or silently re-signed.
        if version != SCHEMA_VERSION {
            return Err(
                StorageError::Backend("unsupported public event cache schema".into()).into(),
            );
        }
        if migrated {
            tx.execute_batch("PRAGMA user_version = 4;")?;
            Self::trim(&tx, &provenance, "")?;
        }
        tx.commit()?;
        Ok(Self {
            conn: Arc::new(CloseableConnection::new(
                conn,
                "public event cache is closed",
            )),
            provenance,
            future_skew,
            refresh: Arc::new(StdMutex::new(RefreshState::default())),
        })
    }

    /// Transactional schema 1 -> 4: add projection version, retained selection
    /// rank and cohort columns, then the bounded, MAC-bound tombstone table and
    /// its authenticated (empty) inventory. Rows whose signed event no longer
    /// verifies are dropped exactly as a read would.
    fn migrate_v1_to_v4(conn: &Connection, provenance: &ProvenanceKey) -> Result<(), AppError> {
        conn.execute_batch(SCHEMA_V4_MIGRATION)?;
        Self::write_inventory(conn, provenance)?;
        let mut statement =
            conn.prepare("SELECT cache_key, event_json FROM public_event_previews")?;
        let rows: Vec<(String, String)> = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (cache_key, json) in rows {
            match parse_verified(&json).filter(supported_target) {
                Some(event) => {
                    let cohort = Self::expected_cohort(&cache_key, &event);
                    conn.execute(
                        "UPDATE public_event_previews
                         SET rank_created_at = ?2, rank_event_id = ?3, cohort_key = ?4
                         WHERE cache_key = ?1",
                        params![
                            cache_key,
                            i64_secs(event.created_at.as_secs()),
                            event.id.to_hex(),
                            cohort
                        ],
                    )?;
                }
                None => {
                    conn.execute(
                        "DELETE FROM public_event_previews WHERE cache_key = ?1",
                        [&cache_key],
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Whether `other` is this same open handle (one account-cache incarnation).
    pub(crate) fn same_incarnation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.conn, &other.conn)
    }

    #[cfg(test)]
    pub(crate) fn lookup(
        &self,
        reference: &PublicEventReference,
        now: u64,
    ) -> Result<Option<PublicEventPreview>, AppError> {
        Ok(self.lookup_state(reference, now)?.into_present())
    }

    #[cfg(test)]
    pub(crate) fn lookup_state(
        &self,
        reference: &PublicEventReference,
        now: u64,
    ) -> Result<PublicEventCacheResult, AppError> {
        let mut results = self.lookup_states(std::slice::from_ref(reference), now)?;
        results.pop().ok_or_else(invalid_reference)
    }

    /// One state per reference, in order. The tombstone inventory is verified
    /// once, under the same connection lock as every read it vouches for.
    pub(crate) fn lookup_states(
        &self,
        references: &[PublicEventReference],
        now: u64,
    ) -> Result<Vec<PublicEventCacheResult>, AppError> {
        let keys = references
            .iter()
            .map(PublicEventReference::key)
            .collect::<Result<Vec<_>, _>>()?;
        let conn = self.conn.lock()?;
        Self::verify_inventory(&conn, &self.provenance)?;
        keys.iter()
            .zip(references)
            .map(|(key, reference)| {
                Self::read_state(
                    &conn,
                    &self.provenance,
                    key,
                    reference,
                    now,
                    self.future_skew.as_secs(),
                )
            })
            .collect()
    }

    /// The locally selected signed event, if any; used only to locate refresh evidence.
    pub(crate) fn selected_event(
        &self,
        reference: &PublicEventReference,
        now: u64,
    ) -> Result<Option<Event>, AppError> {
        let key = reference.key()?;
        let conn = self.conn.lock()?;
        Ok(
            Self::read_preview(&conn, &key, reference, now, self.future_skew.as_secs())?
                .map(|stored| stored.event),
        )
    }

    pub(crate) fn validate_candidates(candidates: &[String]) -> Result<(), AppError> {
        if candidates.len() > MAX_CANDIDATES
            || candidates.iter().any(|json| json.len() > MAX_EVENT_BYTES)
        {
            return Err(budget_error());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn admit(
        &self,
        reference: &PublicEventReference,
        candidates: &[String],
        now: u64,
    ) -> Result<Option<PublicEventPreview>, AppError> {
        Ok(self.admit_state(reference, candidates, now)?.into_present())
    }

    /// Admit one bounded batch of signed target, NIP-09 deletion and other
    /// evidence. Everything is validated before the single write transaction;
    /// invalid, mismatched, older or fenced candidates never displace state.
    pub(crate) fn admit_state(
        &self,
        reference: &PublicEventReference,
        candidates: &[String],
        now: u64,
    ) -> Result<PublicEventCacheResult, AppError> {
        let key = reference.key()?;
        Self::validate_candidates(candidates)?;
        let skew = self.future_skew.as_secs();
        let latest_allowed = now.saturating_add(skew);
        let verified: Vec<Event> = candidates
            .iter()
            .filter_map(|json| parse_verified(json))
            .filter(|event| event.created_at.as_secs() <= latest_allowed)
            .collect();
        let coordinate_reference = reference.event_id_hex.is_none();
        let provenance: &ProvenanceKey = &self.provenance;
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Every index lookup below trusts the authenticated inventory; this
        // transaction's own writes rewrite it before commit.
        Self::verify_inventory(&tx, provenance)?;
        let previous =
            Self::read_preview(&tx, &key, reference, now, skew)?.map(|stored| stored.event);

        // Only fully verified local events can authenticate a deletion's target
        // author. Optional nevent hints never do.
        let mut known: HashMap<String, Event> = HashMap::new();
        for event in verified
            .iter()
            .filter(|event| reference.matches(event))
            .chain(previous.iter())
        {
            known
                .entry(event.id.to_hex())
                .or_insert_with(|| event.clone());
        }
        let mut coordinates: HashSet<String> =
            known.values().filter_map(event_coordinate_key).collect();
        if coordinate_reference {
            coordinates.insert(key.clone());
        }
        // For a coordinate reference, the best-ranked verified version this
        // admission knows (batch or prior selection) is the selection. Deleting
        // it fences the coordinate even when no selection row existed yet.
        let selected_target: Option<String> = if coordinate_reference {
            let mut best: Option<&Event> = None;
            for event in known.values() {
                if best.is_none_or(|current| beats(&rank(event), &rank(current))) {
                    best = Some(event);
                }
            }
            best.map(|event| event.id.to_hex())
        } else {
            None
        };
        let mut evicted: HashSet<String> = HashSet::new();
        for deletion in verified
            .iter()
            .filter(|event| event.kind.as_u16() == KIND_DELETION)
        {
            Self::apply_deletion(
                &tx,
                provenance,
                deletion,
                &known,
                &coordinates,
                selected_target.as_deref(),
                now,
                &mut evicted,
            )?;
        }

        let previous =
            Self::read_preview(&tx, &key, reference, now, skew)?.map(|stored| stored.event);
        let mut selected: Option<&Event> = None;
        for event in verified.iter().filter(|event| reference.matches(event)) {
            // A cohort evicted in this transaction lost its evidence; its
            // members must not come back from the same batch.
            if evicted.contains(&event_cohort_key(event)) {
                continue;
            }
            if let Some(tombstone) =
                Self::covering_tombstone(&tx, provenance, event, coordinate_reference)?
            {
                let selected_coordinate_target = coordinate_reference
                    && selected_target.as_deref() == Some(event.id.to_hex().as_str());
                if selected_coordinate_target {
                    // Rank-only coverage belongs to the existing deleted target,
                    // not to this older candidate. Promote that authenticated
                    // record without inventing another deletion target/proof.
                    let mut record = tombstone.record;
                    if record.cohort_key == key && !record.fences_selection {
                        record.fences_selection = true;
                        Self::write_tombstone(&tx, provenance, &record, now)?;
                        // The final inventory is rewritten after bounded eviction.
                    }
                } else if !coordinate_reference {
                    evicted.extend(Self::record_event_tombstone(
                        &tx,
                        provenance,
                        event,
                        &tombstone.deletion,
                        false,
                        now,
                    )?);
                }
                continue;
            }
            if selected.is_none_or(|best| beats(&rank(event), &rank(best))) {
                selected = Some(event);
            }
        }
        if selected.is_some_and(|event| evicted.contains(&event_cohort_key(event))) {
            selected = None;
        }
        if let (Some(candidate), Some(old)) = (selected, previous.as_ref()) {
            let (candidate_rank, old_rank) = (rank(candidate), rank(old));
            // An identical selection refreshes its admission time; an older or
            // tie-losing candidate keeps the previous selection.
            if candidate_rank != old_rank && !beats(&candidate_rank, &old_rank) {
                selected = None;
            }
        }
        if let Some(event) = selected {
            Self::write_preview(&tx, &key, event, now)?;
        }
        Self::trim(&tx, provenance, &key)?;
        Self::write_inventory(&tx, provenance)?;
        let result = Self::read_state(&tx, provenance, &key, reference, now, skew)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn close(&self) -> Result<(), AppError> {
        Ok(self.conn.close()?)
    }

    pub(crate) fn begin_refresh(&self, key: &str) -> RefreshAdmission {
        let mut state = self
            .refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(done) = state.inflight.get(key) {
            return RefreshAdmission::Coalesced(done.clone());
        }
        let now = Instant::now();
        if state
            .cooldown_until
            .get(key)
            .is_some_and(|until| *until > now)
        {
            return RefreshAdmission::CoolingDown;
        }
        if state.inflight.len() >= MAX_INFLIGHT_REFRESHES {
            return RefreshAdmission::Saturated;
        }
        let (done, receiver) = watch::channel(());
        state.inflight.insert(key.to_owned(), receiver);
        RefreshAdmission::Lead(RefreshLease {
            state: self.refresh.clone(),
            key: key.to_owned(),
            attempted: false,
            _done: done,
        })
    }

    fn read_state(
        conn: &Connection,
        provenance: &ProvenanceKey,
        key: &str,
        reference: &PublicEventReference,
        now: u64,
        future_skew_secs: u64,
    ) -> Result<PublicEventCacheResult, AppError> {
        if let Some(stored) = Self::read_preview(conn, key, reference, now, future_skew_secs)? {
            if let Some(tombstone) = Self::covering_tombstone(
                conn,
                provenance,
                &stored.event,
                reference.event_id_hex.is_none(),
            )? {
                Self::touch_tombstone(conn, tombstone.cache_key(), now)?;
                return Ok(PublicEventCacheResult::AuthoritativeDeleted(
                    tombstone.projection(),
                ));
            }
            conn.execute(
                "UPDATE public_event_previews SET touched_at = ?2 WHERE cache_key = ?1",
                params![key, i64_secs(now)],
            )?;
            return Ok(PublicEventCacheResult::Present(Box::new(stored.preview)));
        }
        let tombstone = if key.starts_with("address:") {
            Self::coordinate_deletion(conn, provenance, key)?
        } else {
            Self::read_tombstone(conn, provenance, key)?
        };
        Ok(match tombstone {
            Some(tombstone) => {
                Self::touch_tombstone(conn, tombstone.cache_key(), now)?;
                PublicEventCacheResult::AuthoritativeDeleted(tombstone.projection())
            }
            None => PublicEventCacheResult::Missing,
        })
    }

    /// The cohort a preview row stored under `key` must carry.
    fn expected_cohort(key: &str, event: &Event) -> String {
        event_coordinate_key(event).unwrap_or_else(|| key.to_owned())
    }

    fn read_preview(
        conn: &Connection,
        key: &str,
        reference: &PublicEventReference,
        now: u64,
        future_skew_secs: u64,
    ) -> Result<Option<StoredPreview>, AppError> {
        type PreviewRow = (
            Option<String>,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<String>,
        );
        let row: Option<PreviewRow> = conn
            .query_row(
                "SELECT CASE WHEN length(CAST(event_json AS BLOB)) <= 262144 THEN event_json ELSE NULL END,
                 received_at, projection_version, rank_created_at, rank_event_id, cohort_key
                 FROM public_event_previews WHERE cache_key = ?1",
                [key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((json, received, version, rank_created_at, rank_event_id, cohort_key)) = row
        else {
            return Ok(None);
        };
        // A newer build's projection is retained untouched; this build cannot read it.
        if version != i64::from(PUBLIC_EVENT_PROJECTION_VERSION) {
            return Err(unsupported_projection());
        }
        let event = json
            .as_deref()
            .and_then(|json| Event::from_json(json).ok())
            .filter(|event| event.verify().is_ok());
        // Rank and cohort columns are re-derived from the signed event; a row
        // whose columns disagree is malformed and is dropped, so column edits
        // can neither move a selection between cohorts nor alter its fence.
        let Some(event) = event.filter(|event| {
            received >= 0
                && rank_created_at == Some(i64_secs(event.created_at.as_secs()))
                && rank_event_id.as_deref() == Some(event.id.to_hex().as_str())
                && cohort_key.as_deref() == Some(Self::expected_cohort(key, event).as_str())
        }) else {
            conn.execute(
                "DELETE FROM public_event_previews WHERE cache_key = ?1",
                [key],
            )?;
            return Ok(None);
        };
        // A mismatched coordinate must never replace another signed selection.
        if !reference.matches(&event)
            || event.created_at.as_secs() > (received as u64).saturating_add(future_skew_secs)
        {
            return Ok(None);
        }
        let received_at = received as u64;
        Ok(Some(StoredPreview {
            preview: PublicEventPreview {
                event_json: event.as_json(),
                received_at,
                refresh_recommended: reference.event_id_hex.is_none()
                    && now.saturating_sub(received_at) >= ADDRESS_REFRESH_SECONDS,
                author_profile: None,
                projection_version: PUBLIC_EVENT_PROJECTION_VERSION,
            },
            event,
        }))
    }

    /// Read, MAC-check and re-verify one tombstone. Corrupt, tampered or
    /// unknown-format evidence is an error, never a silent miss that could
    /// resurrect deleted content.
    fn read_tombstone(
        conn: &Connection,
        provenance: &ProvenanceKey,
        cache_key: &str,
    ) -> Result<Option<Tombstone>, AppError> {
        let stored = conn
            .query_row(
                &format!(
                    "SELECT {TOMBSTONE_COLUMNS} FROM public_event_tombstones WHERE cache_key = ?1"
                ),
                [cache_key],
                stored_tombstone,
            )
            .optional()?;
        stored
            .map(|stored| Self::check_tombstone(provenance, cache_key, stored)?.authenticate())
            .transpose()
    }

    /// Every tombstone of one cohort, MAC- and structure-checked (not yet
    /// signature-verified). Any tampered row in the cohort fails the read.
    fn cohort_tombstones(
        conn: &Connection,
        provenance: &ProvenanceKey,
        cohort_key: &str,
    ) -> Result<Vec<Tombstone>, AppError> {
        // The cohort cap keeps at most 64 event tombstones plus one coordinate
        // tombstone; anything beyond that is not a state this build writes.
        let limit = MAX_COHORT_TOMBSTONES + 2;
        let mut statement = conn.prepare(&format!(
            "SELECT {TOMBSTONE_COLUMNS} FROM public_event_tombstones
             WHERE cohort_key = ?1 ORDER BY cache_key LIMIT ?2"
        ))?;
        let rows = statement
            .query_map(params![cohort_key, limit], stored_tombstone)?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if rows.len() as i64 >= limit {
            return Err(corrupt_evidence());
        }
        rows.into_iter()
            .map(|stored| {
                let cache_key = stored.record.cache_key.clone();
                Self::check_tombstone(provenance, &cache_key, stored)
            })
            .collect()
    }

    /// Constant-time provenance MAC check first, then the structural
    /// invariants the MAC-bound fields must satisfy. No unsigned field is used
    /// before the MAC verifies.
    fn check_tombstone(
        provenance: &ProvenanceKey,
        cache_key: &str,
        stored: StoredTombstone,
    ) -> Result<Tombstone, AppError> {
        let StoredTombstone {
            record,
            malformed,
            mac,
        } = stored;
        if !provenance.verify(&record, &mac)? {
            return Err(corrupt_evidence());
        }
        if malformed || record.cache_key != cache_key {
            return Err(corrupt_evidence());
        }
        // A newer build's evidence is retained untouched; this build cannot read it.
        if record.projection_version != i64::from(PUBLIC_EVENT_PROJECTION_VERSION) {
            return Err(unsupported_projection());
        }
        if record.deletion_json.len() > MAX_EVENT_BYTES {
            return Err(corrupt_evidence());
        }
        let deletion = Event::from_json(&record.deletion_json)
            .ok()
            .filter(|event| event.kind.as_u16() == KIND_DELETION)
            .ok_or_else(corrupt_evidence)?;
        let received_at = u64::try_from(record.received_at).map_err(|_| corrupt_evidence())?;
        let rank_created_at =
            u64::try_from(record.rank_created_at).map_err(|_| corrupt_evidence())?;
        let target_kind = u32::try_from(record.target_kind)
            .ok()
            .filter(|kind| *kind <= u32::from(u16::MAX) && *kind != u32::from(KIND_DELETION))
            .ok_or_else(corrupt_evidence)?;
        let deleter = deletion.pubkey.to_hex();
        let requested_at = deletion.created_at.as_secs();
        let cohort = record.cohort_key.as_str();
        if let Some(target_id) = cache_key.strip_prefix("event:") {
            let Some((proof_id, proof_pubkey, _)) = &record.proof else {
                return Err(corrupt_evidence());
            };
            if proof_id != target_id
                || record.rank_event_id != target_id
                || *proof_pubkey != deleter
                || !is_hex64(target_id)
            {
                return Err(corrupt_evidence());
            }
            let coordinate = parse_coordinate_key(cohort);
            match coordinate {
                // A coordinate version: the retained cohort must name the
                // target's own kind and author.
                Some((kind, author)) => {
                    if kind != target_kind || author != proof_pubkey.as_str() {
                        return Err(corrupt_evidence());
                    }
                }
                // An immutable event, or an addressable one whose identifier
                // is too long to form a coordinate, is its own cohort and never
                // fences one. Replaceable kinds always form a coordinate.
                None => {
                    if cohort != cache_key || record.fences_selection || is_replaceable(target_kind)
                    {
                        return Err(corrupt_evidence());
                    }
                }
            }
            let direct = deletion_targets_event(&deletion, target_id);
            let via_coordinate = coordinate.is_some()
                && deletion_targets_coordinate(&deletion, cohort)
                && rank_created_at <= requested_at;
            if !(direct || via_coordinate) {
                return Err(corrupt_evidence());
            }
        } else if cache_key.starts_with("address:") {
            let Some((kind, author)) = parse_coordinate_key(cache_key) else {
                return Err(corrupt_evidence());
            };
            if record.proof.is_some()
                || cohort != cache_key
                || kind != target_kind
                || author != deleter
                || !record.fences_selection
                || !deletion_targets_coordinate(&deletion, cache_key)
                || rank_created_at != requested_at
                || record.rank_event_id != deletion.id.to_hex()
            {
                return Err(corrupt_evidence());
            }
        } else {
            return Err(corrupt_evidence());
        }
        Ok(Tombstone {
            record,
            deletion,
            received_at,
            rank_created_at,
        })
    }

    /// MAC-bind and store one tombstone record. Only records built from
    /// locally verified evidence reach this function.
    fn write_tombstone(
        conn: &Connection,
        provenance: &ProvenanceKey,
        record: &TombstoneRecord,
        now: u64,
    ) -> Result<(), AppError> {
        if record.cache_key.len() > MAX_STORAGE_KEY_BYTES
            || record.cohort_key.len() > MAX_STORAGE_KEY_BYTES
        {
            return Err(budget_error());
        }
        let tag = provenance.tag(record)?;
        let bytes = tombstone_logical_bytes(record, tag.len());
        if bytes > MAX_TOMBSTONE_BYTES {
            return Err(budget_error());
        }
        let (proof_id, proof_pubkey, proof_sig) = match &record.proof {
            Some((id, pubkey, sig)) => (Some(id), Some(pubkey), Some(sig)),
            None => (None, None, None),
        };
        conn.execute(
            "INSERT INTO public_event_tombstones (cache_key, cohort_key, deletion_json,
                 received_at, touched_at, bytes, projection_version, proof_event_id,
                 proof_pubkey, proof_sig, target_kind, rank_created_at, rank_event_id,
                 fences_selection, provenance_mac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(cache_key) DO UPDATE SET
                 cohort_key = excluded.cohort_key,
                 deletion_json = excluded.deletion_json,
                 received_at = excluded.received_at,
                 touched_at = excluded.touched_at,
                 bytes = excluded.bytes,
                 projection_version = excluded.projection_version,
                 proof_event_id = excluded.proof_event_id,
                 proof_pubkey = excluded.proof_pubkey,
                 proof_sig = excluded.proof_sig,
                 target_kind = excluded.target_kind,
                 rank_created_at = excluded.rank_created_at,
                 rank_event_id = excluded.rank_event_id,
                 fences_selection = excluded.fences_selection,
                 provenance_mac = excluded.provenance_mac",
            params![
                record.cache_key,
                record.cohort_key,
                record.deletion_json,
                record.received_at,
                i64_secs(now),
                bytes as i64,
                record.projection_version,
                proof_id,
                proof_pubkey,
                proof_sig,
                record.target_kind,
                record.rank_created_at,
                record.rank_event_id,
                i64::from(record.fences_selection),
                tag,
            ],
        )?;
        Ok(())
    }

    /// The keyed inventory MAC over every tombstone's indexing fields, sorted by
    /// `cache_key`, with the row count. Reads only the covering inventory index
    /// (bounded keys and row MACs), never signed payloads; more than 1,024 rows
    /// is not a state this build writes and fails closed.
    fn inventory_mac(
        conn: &Connection,
        provenance: &ProvenanceKey,
    ) -> Result<(i64, Hmac<Sha256>), AppError> {
        let mut mac = provenance.keyed()?;
        put_mac_field(&mut mac, INVENTORY_MAC_DOMAIN);
        let mut statement = conn.prepare(INVENTORY_SCAN_SQL)?;
        let mut rows = statement.query([MAX_ENTRIES + 1])?;
        let mut count: i64 = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            if count > MAX_ENTRIES {
                return Err(corrupt_evidence());
            }
            let cache_key: String = row.get(0)?;
            let cohort_key: String = row.get(1)?;
            let row_mac: Vec<u8> = row.get(2)?;
            put_mac_field(&mut mac, cache_key.as_bytes());
            put_mac_field(&mut mac, cohort_key.as_bytes());
            put_mac_field(&mut mac, &row_mac);
        }
        put_mac_field(&mut mac, &count.to_be_bytes());
        Ok((count, mac))
    }

    /// Check the authenticated inventory in constant time before any index is
    /// trusted to include or exclude tombstones. Missing, stale or forged
    /// inventories fail closed.
    fn verify_inventory(conn: &Connection, provenance: &ProvenanceKey) -> Result<(), AppError> {
        let stored: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT tombstone_count, inventory_mac FROM public_event_tombstone_inventory
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_count, tag)) = stored else {
            return Err(corrupt_evidence());
        };
        let (count, mac) = Self::inventory_mac(conn, provenance)?;
        if stored_count != count
            || tag.len() != PROVENANCE_MAC_BYTES
            || mac.verify_slice(&tag).is_err()
        {
            return Err(corrupt_evidence());
        }
        Ok(())
    }

    /// Re-authenticate the inventory after this transaction's own legitimate
    /// tombstone writes and evictions; the caller verified it on entry.
    fn write_inventory(conn: &Connection, provenance: &ProvenanceKey) -> Result<(), AppError> {
        let (count, mac) = Self::inventory_mac(conn, provenance)?;
        let tag = mac.finalize().into_bytes().to_vec();
        conn.execute(
            "INSERT INTO public_event_tombstone_inventory (singleton, tombstone_count, inventory_mac)
             VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET
                 tombstone_count = excluded.tombstone_count,
                 inventory_mac = excluded.inventory_mac",
            params![count, tag],
        )?;
        Ok(())
    }

    fn touch_tombstone(conn: &Connection, cache_key: &str, now: u64) -> Result<(), AppError> {
        conn.execute(
            "UPDATE public_event_tombstones SET touched_at = ?2 WHERE cache_key = ?1",
            params![cache_key, i64_secs(now)],
        )?;
        Ok(())
    }

    /// Deletion evidence for a coordinate with no current selection: the
    /// best-ranked coordinate deletion or selection-fencing version deletion.
    /// The whole cohort is MAC-checked so a tampered row cannot be skipped.
    fn coordinate_deletion(
        conn: &Connection,
        provenance: &ProvenanceKey,
        coordinate_key: &str,
    ) -> Result<Option<Tombstone>, AppError> {
        best_ranked(
            Self::cohort_tombstones(conn, provenance, coordinate_key)?
                .into_iter()
                .filter(|tombstone| {
                    tombstone.cache_key() == coordinate_key || tombstone.record.fences_selection
                }),
        )
        .map(Tombstone::authenticate)
        .transpose()
    }

    /// The best-ranked deleted version of a coordinate. Equal or older versions
    /// may not be selected again.
    fn rank_fence(
        conn: &Connection,
        provenance: &ProvenanceKey,
        coordinate_key: &str,
    ) -> Result<Option<Tombstone>, AppError> {
        best_ranked(
            Self::cohort_tombstones(conn, provenance, coordinate_key)?
                .into_iter()
                .filter(|tombstone| tombstone.cache_key().starts_with("event:")),
        )
        .map(Tombstone::authenticate)
        .transpose()
    }

    fn covering_tombstone(
        conn: &Connection,
        provenance: &ProvenanceKey,
        event: &Event,
        apply_rank_fence: bool,
    ) -> Result<Option<Tombstone>, AppError> {
        let id = event.id.to_hex();
        if let Some(tombstone) = Self::read_tombstone(conn, provenance, &format!("event:{id}"))? {
            return Ok(Some(tombstone));
        }
        let Some(coordinate) = event_coordinate_key(event) else {
            return Ok(None);
        };
        if let Some(tombstone) = Self::read_tombstone(conn, provenance, &coordinate)?
            && event.created_at.as_secs() <= tombstone.rank_created_at
        {
            return Ok(Some(tombstone));
        }
        if apply_rank_fence
            && let Some(tombstone) = Self::rank_fence(conn, provenance, &coordinate)?
            && !beats(&rank(event), &tombstone.rank())
        {
            return Ok(Some(tombstone));
        }
        Ok(None)
    }

    /// Apply one verified kind-5 request. Cohorts evicted anywhere in this
    /// admission cannot regain partial evidence from a later deletion.
    #[allow(clippy::too_many_arguments)]
    fn apply_deletion(
        conn: &Connection,
        provenance: &ProvenanceKey,
        deletion: &Event,
        known: &HashMap<String, Event>,
        coordinates: &HashSet<String>,
        selected_target: Option<&str>,
        now: u64,
        evicted: &mut HashSet<String>,
    ) -> Result<(), AppError> {
        if deletion.as_json().len() > MAX_EVENT_BYTES {
            return Ok(());
        }
        let deleter = deletion.pubkey.to_hex();
        for tag in deletion.tags.iter() {
            let values = tag.as_slice();
            let (Some(name), Some(value)) = (values.first(), values.get(1)) else {
                continue;
            };
            match name.as_str() {
                "e" => {
                    let Some(id) = normalized_hex64(value) else {
                        continue;
                    };
                    let Some(target) = known.get(&id) else {
                        continue;
                    };
                    // NIP-09: same author only, and a deletion of a deletion
                    // has no effect.
                    if target.pubkey != deletion.pubkey || target.kind.as_u16() == KIND_DELETION {
                        continue;
                    }
                    if evicted.contains(&event_cohort_key(target)) {
                        continue;
                    }
                    evicted.extend(Self::record_event_tombstone(
                        conn,
                        provenance,
                        target,
                        deletion,
                        selected_target == Some(id.as_str()),
                        now,
                    )?);
                }
                "a" => {
                    let Some((coordinate, author)) = parse_a_tag(value) else {
                        continue;
                    };
                    if author != deleter
                        || !coordinates.contains(&coordinate)
                        || evicted.contains(&coordinate)
                    {
                        continue;
                    }
                    evicted.extend(Self::record_coordinate_tombstone(
                        conn,
                        provenance,
                        &coordinate,
                        deletion,
                        now,
                    )?);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The stored selection of a coordinate, re-verified against its key.
    /// A row that no longer verifies is dropped.
    fn stored_selection(conn: &Connection, coordinate: &str) -> Result<Option<Event>, AppError> {
        let json: Option<String> = conn
            .query_row(
                "SELECT event_json FROM public_event_previews WHERE cache_key = ?1",
                [coordinate],
                |row| row.get(0),
            )
            .optional()?;
        let Some(json) = json else {
            return Ok(None);
        };
        match parse_verified(&json)
            .filter(|event| event_coordinate_key(event).as_deref() == Some(coordinate))
        {
            Some(event) => Ok(Some(event)),
            None => {
                conn.execute(
                    "DELETE FROM public_event_previews WHERE cache_key = ?1",
                    [coordinate],
                )?;
                Ok(None)
            }
        }
    }

    /// Delete one verified target and every retained alias atomically, keeping
    /// its compact authorship proof and MAC-bound admission provenance as the
    /// fence. `selected_target` says the target is the coordinate selection
    /// this admission verified, which fences the coordinate even when no
    /// selection row existed. Returns the cohort if it was evicted whole.
    fn record_event_tombstone(
        conn: &Connection,
        provenance: &ProvenanceKey,
        target: &Event,
        deletion: &Event,
        selected_target: bool,
        now: u64,
    ) -> Result<Option<String>, AppError> {
        let deletion_json = deletion.as_json();
        if deletion_json.len() > MAX_EVENT_BYTES || target.kind.as_u16() == KIND_DELETION {
            return Ok(None);
        }
        let id = target.id.to_hex();
        let cache_key = format!("event:{id}");
        let coordinate = event_coordinate_key(target);
        let cohort = event_cohort_key(target);
        let target_rank = rank(target);
        let mut fences_selection = false;
        if let Some(coordinate) = &coordinate {
            fences_selection = selected_target;
            // The deleted version fences its coordinate: a selection it equals
            // or supersedes goes too, so older replacements cannot reappear.
            if let Some(selection) = Self::stored_selection(conn, coordinate)? {
                let selection_rank = rank(&selection);
                if selection_rank == target_rank || beats(&target_rank, &selection_rank) {
                    conn.execute(
                        "DELETE FROM public_event_previews WHERE cache_key = ?1",
                        [coordinate],
                    )?;
                    fences_selection = true;
                }
            }
        }
        let record = match Self::read_tombstone(conn, provenance, &cache_key)? {
            // First authenticated evidence wins; later evidence can only add
            // the selection fence.
            Some(existing) => TombstoneRecord {
                fences_selection: existing.record.fences_selection || fences_selection,
                ..existing.record
            },
            None => TombstoneRecord {
                cache_key: cache_key.clone(),
                cohort_key: cohort.clone(),
                deletion_json,
                received_at: i64_secs(now),
                projection_version: i64::from(PUBLIC_EVENT_PROJECTION_VERSION),
                proof: Some((id.clone(), target.pubkey.to_hex(), target.sig.to_string())),
                target_kind: i64::from(target.kind.as_u16()),
                rank_created_at: i64_secs(target.created_at.as_secs()),
                rank_event_id: id.clone(),
                fences_selection,
            },
        };
        Self::write_tombstone(conn, provenance, &record, now)?;
        conn.execute(
            "DELETE FROM public_event_previews WHERE cache_key = ?1 OR rank_event_id = ?2",
            params![cache_key, id],
        )?;
        Self::evict_overfull_cohort(conn, &cohort)
    }

    /// Record a coordinate deletion covering versions up to its request time and
    /// convert covered event-ID aliases into proof-carrying tombstones. Returns
    /// cohorts evicted whole.
    fn record_coordinate_tombstone(
        conn: &Connection,
        provenance: &ProvenanceKey,
        coordinate: &str,
        deletion: &Event,
        now: u64,
    ) -> Result<HashSet<String>, AppError> {
        let mut evicted = HashSet::new();
        let deletion_json = deletion.as_json();
        let Some((kind, _)) = parse_coordinate_key(coordinate) else {
            return Ok(evicted);
        };
        if deletion_json.len() > MAX_EVENT_BYTES {
            return Ok(evicted);
        }
        let requested_at = deletion.created_at.as_secs();
        let existing = Self::read_tombstone(conn, provenance, coordinate)?;
        if existing
            .as_ref()
            .is_none_or(|existing| requested_at > existing.rank_created_at)
        {
            let record = TombstoneRecord {
                cache_key: coordinate.to_owned(),
                cohort_key: coordinate.to_owned(),
                deletion_json,
                received_at: i64_secs(now),
                projection_version: i64::from(PUBLIC_EVENT_PROJECTION_VERSION),
                proof: None,
                target_kind: i64::from(kind),
                rank_created_at: i64_secs(requested_at),
                rank_event_id: deletion.id.to_hex(),
                fences_selection: true,
            };
            Self::write_tombstone(conn, provenance, &record, now)?;
        }
        let effective =
            Self::read_tombstone(conn, provenance, coordinate)?.ok_or_else(corrupt_evidence)?;
        let fence = effective.rank_created_at;
        let mut statement = conn.prepare(
            "SELECT event_json FROM public_event_previews
             WHERE cohort_key = ?1 AND substr(cache_key, 1, 6) = 'event:'",
        )?;
        let aliases: Vec<String> = statement
            .query_map([coordinate], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for json in aliases {
            // Coverage is decided from the signed alias itself, never from
            // unsigned row columns.
            let Some(event) = parse_verified(&json).filter(|event| {
                event_coordinate_key(event).as_deref() == Some(coordinate)
                    && event.created_at.as_secs() <= fence
            }) else {
                continue;
            };
            if let Some(cohort) = Self::record_event_tombstone(
                conn,
                provenance,
                &event,
                &effective.deletion,
                false,
                now,
            )? {
                evicted.insert(cohort);
                return Ok(evicted);
            }
        }
        if let Some(selection) = Self::stored_selection(conn, coordinate)?
            && selection.created_at.as_secs() <= fence
        {
            conn.execute(
                "DELETE FROM public_event_previews WHERE cache_key = ?1",
                [coordinate],
            )?;
        }
        Ok(evicted)
    }

    /// A coordinate whose event-ID tombstones exceed the cap is evicted whole:
    /// selection, aliases and every tombstone. Dropping only the oldest
    /// evidence would let that version return by exact ID while newer members
    /// of the cohort were still retained.
    fn evict_overfull_cohort(conn: &Connection, cohort: &str) -> Result<Option<String>, AppError> {
        if !cohort.starts_with("address:") {
            return Ok(None);
        }
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM public_event_tombstones
             WHERE cohort_key = ?1 AND substr(cache_key, 1, 6) = 'event:'",
            [cohort],
            |row| row.get(0),
        )?;
        if count <= MAX_COHORT_TOMBSTONES {
            return Ok(None);
        }
        Self::evict_cohort(conn, cohort)?;
        Ok(Some(cohort.to_owned()))
    }

    /// Remove one cohort completely, ending local deletion knowledge for it.
    fn evict_cohort(conn: &Connection, cohort: &str) -> Result<(), AppError> {
        conn.execute(
            "DELETE FROM public_event_previews
             WHERE cache_key = ?1 OR coalesce(cohort_key, cache_key) = ?1",
            [cohort],
        )?;
        conn.execute(
            "DELETE FROM public_event_tombstones WHERE cohort_key = ?1",
            [cohort],
        )?;
        Ok(())
    }

    fn write_preview(
        conn: &Connection,
        key: &str,
        event: &Event,
        now: u64,
    ) -> Result<(), AppError> {
        let event_json = event.as_json();
        if event_json.len() > MAX_EVENT_BYTES {
            return Err(
                StorageError::Serialization("public event exceeds its budget".into()).into(),
            );
        }
        let cohort = Self::expected_cohort(key, event);
        conn.execute(
            "INSERT INTO public_event_previews (cache_key, event_json, received_at, touched_at,
                 bytes, projection_version, rank_created_at, rank_event_id, cohort_key)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(cache_key) DO UPDATE SET event_json = excluded.event_json,
                 received_at = excluded.received_at, touched_at = excluded.touched_at,
                 bytes = excluded.bytes, projection_version = excluded.projection_version,
                 rank_created_at = excluded.rank_created_at,
                 rank_event_id = excluded.rank_event_id, cohort_key = excluded.cohort_key",
            params![
                key,
                event_json,
                i64_secs(now),
                event_json.len() as i64,
                i64::from(PUBLIC_EVENT_PROJECTION_VERSION),
                i64_secs(event.created_at.as_secs()),
                event.id.to_hex(),
                cohort,
            ],
        )?;
        Ok(())
    }

    /// Logical record count and bytes of everything retained. Bytes are
    /// recomputed from stored field lengths on every call; a stored `bytes`
    /// value may only raise a row's charge, never lower it.
    fn retained_totals(conn: &Connection) -> Result<(i64, i64), AppError> {
        Ok(conn.query_row(
            &format!(
                "SELECT (SELECT count(*) FROM public_event_previews)
                      + (SELECT count(*) FROM public_event_tombstones),
                        (SELECT coalesce(sum(max(bytes, {PREVIEW_LOGICAL_BYTES_SQL})), 0)
                         FROM public_event_previews)
                      + (SELECT coalesce(sum(max(bytes, {TOMBSTONE_LOGICAL_BYTES_SQL})), 0)
                         FROM public_event_tombstones)"
            ),
            [],
            |row| Ok((row.get(0)?, row.get::<_, i64>(1)? + INVENTORY_BYTES)),
        )?)
    }

    /// Keep previews plus tombstones within 1,024 records and 32 MiB, evicting
    /// least-recently-touched cohorts whole so deletion evidence never outlives
    /// or undercuts the selections that depend on it. Evicting any tombstone
    /// re-authenticates the inventory in the same transaction.
    fn trim(
        conn: &Connection,
        provenance: &ProvenanceKey,
        protected: &str,
    ) -> Result<(), AppError> {
        let tombstones_before: i64 =
            conn.query_row("SELECT count(*) FROM public_event_tombstones", [], |row| {
                row.get(0)
            })?;
        Self::trim_cohorts(conn, protected)?;
        let tombstones_after: i64 =
            conn.query_row("SELECT count(*) FROM public_event_tombstones", [], |row| {
                row.get(0)
            })?;
        if tombstones_after != tombstones_before {
            Self::write_inventory(conn, provenance)?;
        }
        Ok(())
    }

    fn trim_cohorts(conn: &Connection, protected: &str) -> Result<(), AppError> {
        let protected_cohort = conn
            .query_row(
                "SELECT coalesce(cohort_key, cache_key) FROM public_event_previews
                 WHERE cache_key = ?1
                 UNION ALL
                 SELECT cohort_key FROM public_event_tombstones WHERE cache_key = ?1
                 LIMIT 1",
                [protected],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| protected.to_owned());
        loop {
            let (count, bytes) = Self::retained_totals(conn)?;
            if count <= MAX_ENTRIES && bytes <= MAX_TOTAL_BYTES {
                return Ok(());
            }
            let victim: Option<String> = conn
                .query_row(
                    "SELECT cohort FROM (
                         SELECT coalesce(cohort_key, cache_key) AS cohort, touched_at
                         FROM public_event_previews
                         UNION ALL
                         SELECT cohort_key AS cohort, touched_at FROM public_event_tombstones
                     ) WHERE cohort != ?1 ORDER BY touched_at, cohort LIMIT 1",
                    [&protected_cohort],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(victim) = victim else {
                return Err(StorageError::Backend(
                    "public event cache cannot meet its budget".into(),
                )
                .into());
            };
            Self::evict_cohort(conn, &victim)?;
        }
    }
}

#[cfg(test)]
mod tests;

impl MarmotApp {
    pub(crate) fn public_event_cache_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join("public-events-v1.sqlite3")
    }

    pub(crate) fn public_event_cache_for_account(
        &self,
        account: &AccountSummary,
    ) -> Result<PublicEventCache, AppError> {
        self.ensure_storage_open("public event cache")?;
        if let Some(cache) = self
            .public_event_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account.label)
            .cloned()
        {
            return Ok(cache);
        }
        let _lifecycle = self.begin_storage_open("public event cache")?;
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "public_event_cache_handle_open",
            method = "public_event_cache_for_account"
        )
        .entered();
        let path = self.public_event_cache_path(&account.label);
        let lock = crate::sqlcipher::database_open_lock(&path);
        let database = lock.lock();
        if let Some(cache) = self
            .public_event_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account.label)
            .cloned()
        {
            return Ok(cache);
        }
        let key = if account.local_signing {
            let keys = self.account_home().load_signing_keys(&account.label)?;
            self.sqlcipher_key_locked(
                &account.label,
                &keys,
                &database,
                SqlcipherDatabaseKind::PublicEventCache,
            )?
        } else {
            self.external_sqlcipher_key(
                &account.label,
                &account.account_id_hex,
                &database,
                SqlcipherDatabaseKind::PublicEventCache,
            )?
        };
        let cache = PublicEventCache::open(&path, &key, self.config.directory_max_future_skew)?;
        // Publishing under `_lifecycle` is what keeps this cache reachable by a
        // later `close_storage`; see `MarmotApp::begin_storage_open`.
        let mut caches = self
            .public_event_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(caches
            .entry(account.label.clone())
            .or_insert_with(|| cache.clone())
            .clone())
    }

    /// Whether `cache` is still the published handle for `label`. Removal,
    /// wipe, reimport, setup rollback and terminal close all replace or drop
    /// the handle, so this is the account-incarnation fence for late writes.
    pub(crate) fn public_event_cache_is_current(
        &self,
        label: &str,
        cache: &PublicEventCache,
    ) -> bool {
        self.public_event_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .is_some_and(|current| current.same_incarnation(cache))
    }

    /// One read per reference in input order, duplicates included. The cache
    /// and directory handles are acquired once for the batch.
    pub(crate) fn cached_public_events_for_account(
        &self,
        account: &AccountSummary,
        references: &[PublicEventReference],
    ) -> Result<Vec<PublicEventCacheRead>, AppError> {
        if references.is_empty() {
            return Ok(Vec::new());
        }
        let cache = self.public_event_cache_for_account(account)?;
        self.cached_public_events_with_cache(account, &cache, references)
    }

    pub(crate) fn cached_public_events_with_cache(
        &self,
        account: &AccountSummary,
        cache: &PublicEventCache,
        references: &[PublicEventReference],
    ) -> Result<Vec<PublicEventCacheRead>, AppError> {
        let now = unix_now();
        // One lock and one inventory verification for the whole batch.
        let results = cache.lookup_states(references, now)?;
        let mut reads = Vec::with_capacity(references.len());
        for (reference, result) in references.iter().zip(results) {
            reads.push(PublicEventCacheRead {
                key: reference.cache_key()?,
                result,
            });
        }
        self.attach_author_profiles(account, &mut reads);
        Ok(reads)
    }

    pub(crate) fn admit_public_events_for_account(
        &self,
        account: &AccountSummary,
        reference: &PublicEventReference,
        candidates: &[String],
    ) -> Result<PublicEventCacheRead, AppError> {
        let cache = self.public_event_cache_for_account(account)?;
        self.admit_public_events_with_cache(account, &cache, reference, candidates)
    }

    pub(crate) fn admit_public_events_with_cache(
        &self,
        account: &AccountSummary,
        cache: &PublicEventCache,
        reference: &PublicEventReference,
        candidates: &[String],
    ) -> Result<PublicEventCacheRead, AppError> {
        let key = reference.cache_key()?;
        let result = cache.admit_state(reference, candidates, unix_now())?;
        if let PublicEventCacheResult::Present(preview) = &result
            && let Ok(selected) = Event::from_json(&preview.event_json)
        {
            let author = selected.pubkey.to_hex();
            let metadata: Vec<Event> = candidates
                .iter()
                .filter_map(|json| parse_verified(json))
                .filter(|event| event.kind.as_u16() == KIND_METADATA)
                .collect();
            // Only the selected author's kind-0 enters the account's existing
            // directory store; a metadata failure never hides verified content.
            if !metadata.is_empty()
                && let Err(error) =
                    self.remember_account_profile_events(account, &author, &metadata)
            {
                tracing::debug!(
                    target: "marmot_app::directory",
                    method = "admit_public_events_with_cache",
                    error_kind = error.privacy_safe_kind(),
                    "public event author metadata was not cached"
                );
            }
        }
        let mut reads = vec![PublicEventCacheRead { key, result }];
        self.attach_author_profiles(account, &mut reads);
        reads.pop().ok_or_else(invalid_reference)
    }

    fn attach_author_profiles(&self, account: &AccountSummary, reads: &mut [PublicEventCacheRead]) {
        let authors: BTreeSet<String> = reads
            .iter()
            .filter_map(|read| match &read.result {
                PublicEventCacheResult::Present(preview) => Event::from_json(&preview.event_json)
                    .ok()
                    .map(|event| event.pubkey.to_hex()),
                _ => None,
            })
            .collect();
        if authors.is_empty() {
            return;
        }
        let authors: Vec<String> = authors.into_iter().collect();
        // Enrichment is best effort and local-only: no profile request starts here.
        let Ok(profiles) = self.account_scoped_profiles(account, &authors) else {
            return;
        };
        for read in reads {
            if let PublicEventCacheResult::Present(preview) = &mut read.result
                && let Ok(event) = Event::from_json(&preview.event_json)
            {
                preview.author_profile = profiles.get(&event.pubkey.to_hex()).cloned();
            }
        }
    }

    /// Up to four safe relays: at most two ephemeral reference hints, then the
    /// configured directory relays. Every endpoint passes the relay-plane
    /// host-safety rule (retired hosts, plaintext and loopback policy).
    pub(crate) fn public_event_query_relays(&self, hints: &[String]) -> Vec<TransportEndpoint> {
        let hints = self.retain_safe_discovered_endpoints(
            hints
                .iter()
                .take(PUBLIC_EVENT_QUERY_MAX_RELAYS)
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "public event hint",
        );
        let configured = self.retain_safe_discovered_endpoints(
            self.directory_source_relays(&[]),
            "public event query",
        );
        let mut relays: Vec<TransportEndpoint> = Vec::new();
        for endpoint in hints.into_iter().take(MAX_HINT_RELAYS).chain(configured) {
            if relays.len() == PUBLIC_EVENT_QUERY_MAX_RELAYS {
                break;
            }
            if !relays.contains(&endpoint) {
                relays.push(endpoint);
            }
        }
        relays
    }

    /// Bounded network evidence for one reference: the exact ID or complete
    /// coordinate, then kind-5 `#e`/`#a` requests and kind-0 metadata from the
    /// actual target author only. Never recursive, ten seconds and sixteen
    /// received events / 4 MiB overall. Returns candidates for admission; it
    /// writes nothing.
    pub(crate) async fn fetch_public_event_candidates(
        &self,
        reference: &PublicEventReference,
        hints: &[String],
        known: Option<&Event>,
    ) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + RESOLVE_DEADLINE;
        let Ok(key) = reference.cache_key() else {
            return Vec::new();
        };
        let relays = self.public_event_query_relays(hints);
        if relays.is_empty() {
            return Vec::new();
        }
        let (target_filter, mut author, mut coordinate) = match &key {
            PublicEventCacheKey::EventId { event_id_hex } => (
                PublicEventQueryFilter::EventId {
                    event_id_hex: event_id_hex.clone(),
                },
                None,
                None,
            ),
            PublicEventCacheKey::Coordinate {
                kind,
                author_pubkey_hex,
                identifier,
            } => {
                let Ok(kind) = u16::try_from(*kind) else {
                    return Vec::new();
                };
                (
                    PublicEventQueryFilter::Coordinate {
                        kind,
                        author_hex: author_pubkey_hex.clone(),
                        identifier: identifier.clone(),
                    },
                    Some(author_pubkey_hex.clone()),
                    Some(key.storage_key()),
                )
            }
        };
        let immutable_known = matches!(key, PublicEventCacheKey::EventId { .. }) && known.is_some();
        let mut best: Option<Event> = known.cloned();
        let mut candidates: Vec<String> = Vec::new();
        // One raw-traffic meter for the whole request, shared by every relay
        // and both phases.
        let traffic = PublicEventTrafficMeter::new(REQUEST_TRAFFIC);
        if !immutable_known {
            let outcome = self
                .relay_plane
                .query_public_events(
                    relays.clone(),
                    vec![target_filter],
                    TARGET_PHASE_BUDGET,
                    &traffic,
                    deadline,
                )
                .await;
            for json in outcome.events_json {
                // Only exact signed matches are kept; others never reach admission.
                let Some(event) = verified_event(&json, reference).filter(|event| {
                    event.created_at.as_secs()
                        <= unix_now()
                            .saturating_add(self.config.directory_max_future_skew.as_secs())
                }) else {
                    continue;
                };
                if best
                    .as_ref()
                    .is_none_or(|current| beats(&rank(&event), &rank(current)))
                {
                    best = Some(event);
                }
                candidates.push(json);
            }
        }
        let mut target_ids: Vec<String> = Vec::new();
        for event in known.into_iter().chain(best.as_ref()) {
            author.get_or_insert_with(|| event.pubkey.to_hex());
            if coordinate.is_none() {
                coordinate = event_coordinate_key(event);
            }
            let id = event.id.to_hex();
            if !target_ids.contains(&id) {
                target_ids.push(id);
            }
        }
        // Deletion authority needs the target's actual author; without a
        // verified target there is nothing to authenticate.
        let Some(author) = author else {
            return candidates;
        };
        let mut filters: Vec<PublicEventQueryFilter> = target_ids
            .into_iter()
            .take(2)
            .map(|event_id_hex| PublicEventQueryFilter::EventDeletions {
                event_id_hex,
                author_hex: author.clone(),
            })
            .collect();
        if let Some(value) = coordinate
            .as_deref()
            .and_then(|coordinate| coordinate.strip_prefix("address:"))
        {
            filters.push(PublicEventQueryFilter::CoordinateDeletions {
                coordinate: value.to_owned(),
                author_hex: author.clone(),
            });
        }
        filters.push(PublicEventQueryFilter::AuthorMetadata {
            author_hex: author.clone(),
        });
        let outcome = self
            .relay_plane
            .query_public_events(relays, filters, EVIDENCE_PHASE_BUDGET, &traffic, deadline)
            .await;
        for json in outcome.events_json {
            let Some(event) = parse_verified(&json) else {
                continue;
            };
            let kind = event.kind.as_u16();
            if event.pubkey.to_hex() == author
                && (kind == KIND_DELETION || kind == KIND_METADATA)
                && !candidates.contains(&json)
            {
                candidates.push(json);
            }
        }
        candidates.truncate(MAX_CANDIDATES);
        candidates
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
