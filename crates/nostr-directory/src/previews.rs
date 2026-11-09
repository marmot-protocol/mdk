//! Account-scoped cache of verified public Nostr events referenced from
//! message content (`note`, `nevent`, `naddr` or a hex event ID).
//!
//! Hosts read previews synchronously for their first frame and refresh them
//! asynchronously. Rows live in the account's `app-cache.sqlite3`, so they
//! share the directory cache's keying, close and account-removal lifecycle.
//!
//! Rules:
//! - Only events whose signature verifies and that exactly match the reference
//!   are stored. Cache identity is the event ID or the `(kind, author, d)`
//!   coordinate; relay hints, including an `nevent` author, are only query
//!   inputs and never decide which deletions count.
//! - A coordinate keeps the newest version: higher `created_at`, then the
//!   lower event ID (NIP-01).
//! - NIP-09 deletions count only when signed by the verified event author, in
//!   either form: an `e` tag deletes that exact event (for a coordinate, the
//!   previous version becomes current), an `a` tag deletes every version up to
//!   its own `created_at`. A row keeps the newest `a` deletion time it has seen
//!   (`deleted_through`), even while it shows a newer version, so a relay that
//!   kept an older version cannot restore it. Rows that carry a deletion time
//!   are evicted after other rows, but never the row just written.
//! - The first query goes to the reference's relay hints and the directory
//!   relays. When it finishes without the target, one supplementary query goes
//!   to the deployment's discovery indexers and the author's NIP-65 write
//!   relays (`naddr` author, or an `nevent` author hint): cached, else read
//!   from the indexers. A hit on the first query adds no round trip.
//! - Once a refresh has verified events, one follow-up query asks their author,
//!   on every relay this refresh queried, for deletions the first query could
//!   not attribute.
//! - Not-found results and fetch failures are never stored. A fetch where a
//!   relay did not complete may admit what it found, but never confirms a row,
//!   and an event-ID row it admits is rechecked after 30 minutes.
//! - Event-ID rows from a fetch every relay answered never refetch. Coordinate rows refetch after
//!   30 minutes. Any finished refresh starts a 30-second in-memory cooldown
//!   per key.
//!
//! Author profiles are not part of a preview; hosts read them through the
//! cached-identity API and refresh them through the directory.

use crate::error::{DirectoryError, blocking_directory_task};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cgka_traits::TransportEndpoint;
use cgka_traits::storage::StorageError;
use nostr::event::Event;
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip19::{FromBech32, Nip19};
use nostr::prelude::{EventId, Filter, Kind, PublicKey, RelayUrl};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use transport_nostr::canonical_relay;
use transport_nostr_peeler::NostrTransportEvent;

use super::published_records::relay_list_state_from_event;
use super::resources::{DirectoryAccount, DirectoryResources};
use super::search::SEARCH_MAX_WRITE_RELAYS_PER_AUTHOR;
use super::{Directory, unix_now_seconds};

/// Maximum references in one cached batch read.
pub const MAX_PUBLIC_EVENT_REFERENCES: usize = 16;
/// Longest reference string accepted; longer input is `Unsupported`.
const MAX_REFERENCE_BYTES: usize = 5_000;
/// Largest signed event JSON retained.
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: i64 = 1_024;
const MAX_TOTAL_BYTES: i64 = 16 * 1024 * 1024;
/// Fixed per-row cost on top of the stored JSON, for the byte budget.
const ROW_OVERHEAD_BYTES: i64 = 256;
/// How long a coordinate row, or an event-ID row admitted from an incomplete
/// fetch, stays fresh.
const REFRESH_SECONDS: u64 = 30 * 60;
const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_COOLDOWN_ENTRIES: usize = 256;
/// Reads refresh `touched_at` at most this often, so most reads write nothing.
const TOUCH_INTERVAL_SECONDS: u64 = 60 * 60;
const MAX_HINT_RELAYS: usize = 2;
const MAX_QUERY_RELAYS: usize = 6;
/// Endpoints in the supplementary query: every discovery indexer first, then
/// author write relays in the room left.
const MAX_SUPPLEMENTARY_RELAYS: usize = 8;
/// Kind-10002 versions each indexer returns for one author's relay list: the
/// newest. The read's shared buffer holds one per indexer it asks.
const AUTHOR_RELAY_LIST_EVENTS_PER_INDEXER: usize = 1;
const MAX_FETCHED_EVENTS: usize = 64;
/// Limit on the unattributed kind-5 query for an event ID. A full answer may
/// hide the author's deletion behind other keys' requests.
pub const EVENT_DELETION_QUERY_LIMIT: usize = 16;

/// Local state of one referenced public event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicEventPreview {
    /// A verified signed event, as JSON. `fetched_at` is when a relay last
    /// confirmed it, in Unix seconds.
    Present { event_json: String, fetched_at: u64 },
    /// The author published a NIP-09 deletion request for it.
    Deleted,
    /// Nothing is cached. Not durable truth: a refresh may still find it.
    Missing,
    /// Not a `note`, `nevent`, `naddr` or hex event ID this cache supports.
    Unsupported,
}

/// One result, echoing the reference as the caller passed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicEventPreviewRead {
    pub reference: String,
    pub preview: PublicEventPreview,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    EventId(EventId),
    Coordinate(Coordinate),
}

#[derive(Clone, Debug)]
struct Reference {
    target: Target,
    relay_hints: Vec<TransportEndpoint>,
    /// An `nevent` author. Like relay hints it only routes queries: it never
    /// decides which event is admitted or which deletions count.
    author_hint: Option<PublicKey>,
}

impl Reference {
    /// Whose NIP-65 write relays the supplementary query may ask.
    fn routing_author(&self) -> Option<PublicKey> {
        match &self.target {
            Target::Coordinate(coordinate) => Some(coordinate.public_key),
            Target::EventId(_) => self.author_hint,
        }
    }
}

fn is_replaceable(kind: Kind) -> bool {
    // Local rule: rust-nostr also counts kind 41, which is not replaceable
    // by coordinate in NIP-01.
    let kind = kind.as_u16();
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

fn first_d_tag(event: &Event) -> &str {
    event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .find(|tag| tag.first().is_some_and(|name| name == "d"))
        .and_then(|tag| tag.get(1))
        .map_or("", String::as_str)
}

fn has_tag(event: &Event, name: &str, value: &str) -> bool {
    event.tags.iter().any(|tag| {
        let tag = tag.as_slice();
        tag.first().is_some_and(|n| n == name) && tag.get(1).is_some_and(|v| v == value)
    })
}

/// NIP-01 replaceable ordering: newer `created_at`, then the lower ID.
fn supersedes(candidate: &Event, current: &Event) -> bool {
    (candidate.created_at, std::cmp::Reverse(candidate.id))
        > (current.created_at, std::cmp::Reverse(current.id))
}

fn parse_reference(raw: &str) -> Option<Reference> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_REFERENCE_BYTES {
        return None;
    }
    let raw = raw.strip_prefix("nostr:").unwrap_or(raw);
    if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(Reference {
            target: Target::EventId(EventId::from_hex(raw).ok()?),
            relay_hints: Vec::new(),
            author_hint: None,
        });
    }
    let hints = |relays: &[RelayUrl]| {
        relays
            .iter()
            .map(|relay| TransportEndpoint(relay.to_string()))
            .collect()
    };
    match Nip19::from_bech32(raw).ok()? {
        Nip19::EventId(id) => Some(Reference {
            target: Target::EventId(id),
            relay_hints: Vec::new(),
            author_hint: None,
        }),
        Nip19::Event(event) => Some(Reference {
            target: Target::EventId(event.event_id),
            relay_hints: hints(&event.relays),
            author_hint: event.author,
        }),
        Nip19::Coordinate(naddr) => {
            let kind = naddr.coordinate.kind;
            let supported = kind.is_addressable()
                || (is_replaceable(kind) && naddr.coordinate.identifier.is_empty());
            supported.then(|| Reference {
                target: Target::Coordinate(naddr.coordinate.clone()),
                relay_hints: hints(&naddr.relays),
                author_hint: None,
            })
        }
        _ => None,
    }
}

impl Target {
    fn cache_key(&self) -> String {
        match self {
            Self::EventId(id) => format!("event:{}", id.to_hex()),
            Self::Coordinate(coordinate) => format!("coordinate:{coordinate}"),
        }
    }

    fn matches(&self, event: &Event) -> bool {
        match self {
            Self::EventId(id) => event.id == *id,
            Self::Coordinate(coordinate) => {
                event.kind == coordinate.kind
                    && event.pubkey == coordinate.public_key
                    && (!coordinate.kind.is_addressable()
                        || first_d_tag(event) == coordinate.identifier)
            }
        }
    }

    /// Kind-5 queries. An `nevent` author hint is not trusted to narrow them:
    /// the author is checked against the verified event at admission.
    fn filters(&self, stored: Option<&Event>) -> Vec<Filter> {
        let deletions = || Filter::new().kind(Kind::EventDeletion);
        let mut filters = match self {
            Self::EventId(id) => vec![
                Filter::new().id(*id).limit(1),
                deletions().event(*id).limit(EVENT_DELETION_QUERY_LIMIT),
            ],
            Self::Coordinate(coordinate) => {
                let mut versions = Filter::new()
                    .kind(coordinate.kind)
                    .author(coordinate.public_key)
                    .limit(4);
                if coordinate.kind.is_addressable() {
                    versions = versions.identifier(coordinate.identifier.clone());
                }
                vec![
                    versions,
                    deletions()
                        .author(coordinate.public_key)
                        .coordinate(coordinate)
                        .limit(4),
                ]
            }
        };
        // The other deletion form, for the version already cached.
        if let Some(event) = stored {
            match self {
                Self::EventId(_) => {
                    if let Some(coordinate) = event_coordinate(event) {
                        filters.push(
                            deletions()
                                .author(event.pubkey)
                                .coordinate(&coordinate)
                                .limit(4),
                        );
                    }
                }
                Self::Coordinate(_) => {
                    filters.push(deletions().author(event.pubkey).event(event.id).limit(4));
                }
            }
        }
        filters
    }
}

/// The coordinate an addressable or replaceable event belongs to.
fn event_coordinate(event: &Event) -> Option<Coordinate> {
    if event.kind.is_addressable() {
        Some(Coordinate::new(event.kind, event.pubkey).identifier(first_d_tag(event)))
    } else if is_replaceable(event.kind) {
        Some(Coordinate::new(event.kind, event.pubkey))
    } else {
        None
    }
}

/// The newest deletion by `event`'s author that covers `event`: an `e` tag
/// naming it, or an `a` tag for its coordinate dated at or after it.
fn deletion_time(event: &Event, deletions: &[&Event]) -> Option<u64> {
    let id = event.id.to_hex();
    let coordinate = event_coordinate(event).map(|coordinate| coordinate.to_string());
    deletions
        .iter()
        .filter(|deletion| deletion.pubkey == event.pubkey)
        .filter(|deletion| {
            has_tag(deletion, "e", &id)
                || coordinate.as_deref().is_some_and(|coordinate| {
                    has_tag(deletion, "a", coordinate) && deletion.created_at >= event.created_at
                })
        })
        .map(|deletion| deletion.created_at.as_secs())
        .max()
}

/// One author-scoped kind-5 query for verified events the first query could
/// not cover: an event ID whose unattributed answer came back full (deletions
/// by other keys may hide the author's), the coordinate of an addressable
/// event linked by ID, and `naddr` versions this refresh found.
fn follow_up_deletions(target: &Target, stored: Option<&Event>, fetched: &[Event]) -> Vec<Filter> {
    let deletions = |author| Filter::new().kind(Kind::EventDeletion).author(author);
    match target {
        Target::EventId(id) => {
            let fetched_event = fetched.iter().find(|event| event.id == *id);
            let Some(event) = fetched_event.or(stored) else {
                return Vec::new();
            };
            let mut filters = Vec::new();
            let hex = id.to_hex();
            let answers = fetched
                .iter()
                .filter(|event| event.kind == Kind::EventDeletion && has_tag(event, "e", &hex))
                .collect::<Vec<_>>();
            if answers.len() >= EVENT_DELETION_QUERY_LIMIT
                && !answers.iter().any(|answer| answer.pubkey == event.pubkey)
            {
                filters.push(deletions(event.pubkey).event(*id).limit(4));
            }
            // The first query already asked for the cached event's coordinate.
            if stored.is_none()
                && let Some(coordinate) = event_coordinate(event)
            {
                filters.push(deletions(event.pubkey).coordinate(&coordinate).limit(4));
            }
            filters
        }
        Target::Coordinate(coordinate) => {
            let versions = fetched
                .iter()
                .filter(|event| target.matches(event))
                .filter(|event| stored.is_none_or(|stored| stored.id != event.id))
                .map(|event| event.id)
                .collect::<Vec<_>>();
            if versions.is_empty() {
                return Vec::new();
            }
            vec![deletions(coordinate.public_key).events(versions).limit(8)]
        }
    }
}

/// The first spelling of each relay in `relays`, skipping relays in `exclude`.
/// Relays compare by identity: `wss://relay.example/` and
/// `wss://Relay.Example:443` name `wss://relay.example`.
fn distinct_relays(
    relays: Vec<TransportEndpoint>,
    exclude: &[TransportEndpoint],
) -> Vec<TransportEndpoint> {
    let mut seen = exclude
        .iter()
        .map(|relay| canonical_relay(&relay.0))
        .collect::<HashSet<_>>();
    relays
        .into_iter()
        .filter(|relay| seen.insert(canonical_relay(&relay.0)))
        .collect()
}

/// Verified events from one or more public-event reads, and whether every
/// relay in every read finished.
#[derive(Debug)]
struct Fetched {
    events: Vec<Event>,
    complete: bool,
}

impl Fetched {
    fn new(events: Vec<Event>, complete: bool) -> Self {
        Self { events, complete }
    }

    /// Add another read's events, once each, and its completeness.
    fn merge(&mut self, other: Fetched) {
        let mut seen = self
            .events
            .iter()
            .map(|event| event.id)
            .collect::<HashSet<_>>();
        self.events.extend(
            other
                .events
                .into_iter()
                .filter(|event| seen.insert(event.id)),
        );
        self.complete &= other.complete;
    }
}

/// What the cache holds for one key: the shown event, if any, and the newest
/// deletion time seen. At least one is set.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    event: Option<Box<Event>>,
    deleted_through: Option<u64>,
}

#[derive(Clone, Debug)]
struct Stored {
    row: Row,
    complete: bool,
    fetched_at: u64,
}

impl Stored {
    fn preview(&self) -> PublicEventPreview {
        match &self.row.event {
            Some(event) => PublicEventPreview::Present {
                event_json: event.as_json(),
                fetched_at: self.fetched_at,
            },
            None => PublicEventPreview::Deleted,
        }
    }
}

/// What a refresh leads to for one key.
#[derive(Debug, PartialEq, Eq)]
enum Admitted {
    /// Nothing is known.
    Nothing,
    /// The only known version was deleted by ID and no deletion bound
    /// remains, so the key goes back to unknown.
    Cleared,
    Row(Row),
}

/// The state a refresh leads to, given the stored row and verified events.
fn admit(target: &Target, stored: Option<&Row>, fetched: &[Event]) -> Admitted {
    let deletions = fetched
        .iter()
        .filter(|event| event.kind == Kind::EventDeletion)
        .collect::<Vec<_>>();
    let stored_event = stored.and_then(|row| row.event.as_deref());
    let candidates = fetched
        .iter()
        .filter(|event| target.matches(event) && event.as_json().len() <= MAX_EVENT_BYTES)
        .chain(stored_event);

    match target {
        Target::EventId(_) => {
            // A deleted event ID stays deleted.
            if let Some(row) = stored.filter(|row| row.event.is_none()) {
                return Admitted::Row(row.clone());
            }
            let Some(event) = candidates.into_iter().next() else {
                return Admitted::Nothing;
            };
            Admitted::Row(match deletion_time(event, &deletions) {
                Some(through) => Row {
                    event: None,
                    deleted_through: Some(through),
                },
                None => Row {
                    event: Some(Box::new(event.clone())),
                    deleted_through: None,
                },
            })
        }
        Target::Coordinate(coordinate) => {
            let mut deleted_through = stored.and_then(|row| row.deleted_through);
            let candidates = candidates.collect::<Vec<_>>();
            // An `a` deletion bounds the coordinate even with no version in hand.
            let author = coordinate.public_key;
            let coordinate = coordinate.to_string();
            for deletion in &deletions {
                if deletion.pubkey == author && has_tag(deletion, "a", &coordinate) {
                    deleted_through = deleted_through.max(Some(deletion.created_at.as_secs()));
                }
            }
            // Only an `a` deletion sets the bound. An `e` deletion removes that
            // one version, and the previous version becomes current.
            let mut deleted_by_id = false;
            let shown = candidates
                .into_iter()
                .filter(|event| {
                    deleted_through.is_none_or(|through| event.created_at.as_secs() > through)
                })
                .filter(|event| {
                    let deleted = deletion_time(event, &deletions).is_some();
                    deleted_by_id |= deleted;
                    !deleted
                })
                .fold(None::<&Event>, |best, event| match best {
                    Some(current) if !supersedes(event, current) => Some(current),
                    _ => Some(event),
                });
            match (shown, deleted_through) {
                (None, None) if deleted_by_id => Admitted::Cleared,
                (None, None) => Admitted::Nothing,
                (shown, deleted_through) => Admitted::Row(Row {
                    event: shown.map(|event| Box::new(event.clone())),
                    deleted_through,
                }),
            }
        }
    }
}

fn needs_refresh(target: &Target, stored: Option<&Stored>, now: u64) -> bool {
    let Some(stored) = stored else {
        return true;
    };
    let stale = stored.fetched_at.saturating_add(REFRESH_SECONDS) <= now;
    match target {
        Target::EventId(_) => stored.row.event.is_some() && !stored.complete && stale,
        Target::Coordinate(_) => stale,
    }
}

fn corrupt_row() -> DirectoryError {
    StorageError::Serialization("invalid cached public event".into()).into()
}

fn read_row(conn: &Connection, key: &str) -> Result<Option<Stored>, DirectoryError> {
    let row = conn
        .query_row(
            "SELECT event_json, deleted_through, complete, fetched_at
             FROM public_event_previews WHERE cache_key = ?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((event_json, deleted_through, complete, fetched_at)) = row else {
        return Ok(None);
    };
    let event = event_json
        .map(|json| Event::from_json(json).map(Box::new))
        .transpose()
        .map_err(|_| corrupt_row())?;
    let deleted_through = deleted_through
        .map(u64::try_from)
        .transpose()
        .map_err(|_| corrupt_row())?;
    Ok(Some(Stored {
        row: Row {
            event,
            deleted_through,
        },
        complete,
        fetched_at: u64::try_from(fetched_at).map_err(|_| corrupt_row())?,
    }))
}

/// The host-facing state of one row, without parsing its stored event.
fn read_preview(
    conn: &Connection,
    key: &str,
) -> Result<Option<PublicEventPreview>, DirectoryError> {
    let row = conn
        .query_row(
            "SELECT event_json, fetched_at FROM public_event_previews WHERE cache_key = ?1",
            [key],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((event_json, fetched_at)) = row else {
        return Ok(None);
    };
    Ok(Some(match event_json {
        None => PublicEventPreview::Deleted,
        Some(event_json) => PublicEventPreview::Present {
            event_json,
            fetched_at: u64::try_from(fetched_at).map_err(|_| corrupt_row())?,
        },
    }))
}

fn i64_secs(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Store the outcome of one refresh, inside the caller's transaction. An
/// unchanged row is re-dated only by a complete fetch.
fn persist_refresh(
    conn: &Connection,
    key: &str,
    target: &Target,
    fetched: &[Event],
    complete: bool,
    now: u64,
) -> Result<(), DirectoryError> {
    let stored = read_row(conn, key)?;
    let row = match admit(target, stored.as_ref().map(|stored| &stored.row), fetched) {
        Admitted::Nothing => return Ok(()),
        Admitted::Cleared => {
            conn.execute(
                "DELETE FROM public_event_previews WHERE cache_key = ?1",
                [key],
            )?;
            return Ok(());
        }
        Admitted::Row(row) => row,
    };
    if stored.as_ref().is_some_and(|stored| stored.row == row) {
        if complete {
            conn.execute(
                "UPDATE public_event_previews SET complete = 1, fetched_at = ?2, touched_at = ?2
                 WHERE cache_key = ?1",
                params![key, i64_secs(now)],
            )?;
        }
        return Ok(());
    }
    write_row(conn, key, &row, complete, now)?;
    trim(conn, key)
}

fn write_row(
    conn: &Connection,
    key: &str,
    row: &Row,
    complete: bool,
    now: u64,
) -> Result<(), DirectoryError> {
    let event_json = row.event.as_ref().map(|event| event.as_json());
    let bytes = ROW_OVERHEAD_BYTES
        + i64::try_from(key.len() + event_json.as_ref().map_or(0, String::len)).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO public_event_previews
            (cache_key, event_json, deleted_through, complete, bytes, fetched_at, touched_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(cache_key) DO UPDATE SET
            event_json = excluded.event_json,
            deleted_through = excluded.deleted_through,
            complete = excluded.complete,
            bytes = excluded.bytes,
            fetched_at = excluded.fetched_at,
            touched_at = excluded.touched_at",
        params![
            key,
            event_json,
            row.deleted_through.map(i64_secs),
            complete,
            bytes,
            i64_secs(now),
        ],
    )?;
    Ok(())
}

/// Evict least recently used rows until both budgets hold, rows without a
/// deletion time first. The row just written (`keep`) is never evicted, so a
/// cache full of deletion times still admits new previews.
fn trim(conn: &Connection, keep: &str) -> Result<(), DirectoryError> {
    let (mut count, mut total): (i64, i64) = conn.query_row(
        "SELECT count(*), coalesce(sum(bytes), 0) FROM public_event_previews",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count <= MAX_ENTRIES && total <= MAX_TOTAL_BYTES {
        return Ok(());
    }
    let mut statement = conn.prepare(
        "SELECT cache_key, bytes FROM public_event_previews WHERE cache_key != ?1
         ORDER BY deleted_through IS NOT NULL, touched_at, cache_key",
    )?;
    let mut rows = statement.query([keep])?;
    let mut evict = Vec::new();
    while count > MAX_ENTRIES || total > MAX_TOTAL_BYTES {
        let Some(row) = rows.next()? else { break };
        evict.push(row.get::<_, String>(0)?);
        total -= row.get::<_, i64>(1)?;
        count -= 1;
    }
    drop(rows);
    for key in evict {
        conn.execute(
            "DELETE FROM public_event_previews WHERE cache_key = ?1",
            [key],
        )?;
    }
    Ok(())
}

fn invalid_batch(len: usize) -> DirectoryError {
    DirectoryError::InvalidPublicEventReferences(format!(
        "requested {len} references; maximum is {MAX_PUBLIC_EVENT_REFERENCES}"
    ))
}

impl<R: DirectoryResources> Directory<R> {
    /// Network-free cached previews, one per reference in input order.
    /// Unparseable references are `Unsupported` rows, not errors.
    pub fn cached_public_event_previews(
        &self,
        account: &DirectoryAccount,
        references: &[String],
    ) -> Result<Vec<PublicEventPreviewRead>, DirectoryError> {
        if references.len() > MAX_PUBLIC_EVENT_REFERENCES {
            return Err(invalid_batch(references.len()));
        }
        let keys = references
            .iter()
            .map(|reference| parse_reference(reference).map(|parsed| parsed.target.cache_key()))
            .collect::<Vec<_>>();
        let mut found = HashMap::new();
        if keys.iter().any(Option::is_some) {
            let cache = self.resources.cache_for_account(account)?;
            let mut conn = cache.lock()?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let now = unix_now_seconds();
            let unique = keys.iter().flatten().collect::<HashSet<_>>();
            for key in unique {
                if let Some(preview) = read_preview(&tx, key)? {
                    found.insert(key.clone(), preview);
                }
            }
            if !found.is_empty() {
                for key in found.keys() {
                    tx.execute(
                        "UPDATE public_event_previews SET touched_at = ?2
                         WHERE cache_key = ?1 AND touched_at < ?3",
                        params![
                            key,
                            i64_secs(now),
                            i64_secs(now.saturating_sub(TOUCH_INTERVAL_SECONDS))
                        ],
                    )?;
                }
            }
            tx.commit()?;
        }
        Ok(references
            .iter()
            .zip(keys)
            .map(|(reference, key)| PublicEventPreviewRead {
                reference: reference.clone(),
                preview: match key {
                    None => PublicEventPreview::Unsupported,
                    Some(key) => found
                        .get(&key)
                        .cloned()
                        .unwrap_or(PublicEventPreview::Missing),
                },
            })
            .collect())
    }

    /// Refresh one reference from relays when it is missing or stale, then
    /// return its local state. A failed or empty fetch keeps prior content.
    ///
    /// `discovery_indexers` are the deployment's public indexers, used only by
    /// the supplementary query when the first one misses. They are empty on a
    /// neutral deployment, which then never dials an indexer.
    pub async fn resolve_public_event_preview(
        &self,
        account: &DirectoryAccount,
        reference: &str,
        discovery_indexers: &[TransportEndpoint],
    ) -> Result<PublicEventPreviewRead, DirectoryError> {
        let read = |preview| PublicEventPreviewRead {
            reference: reference.to_owned(),
            preview,
        };
        let Some(parsed) = parse_reference(reference) else {
            return Ok(read(PublicEventPreview::Unsupported));
        };
        let key = parsed.target.cache_key();
        let stored = {
            let resources = self.resources.clone();
            let account = account.clone();
            let key = key.clone();
            blocking_directory_task(move || {
                let cache = resources.cache_for_account(&account)?;
                let conn = cache.lock()?;
                read_row(&conn, &key)
            })
            .await?
        };
        let current = |stored: Option<&Stored>| {
            read(stored.map_or(PublicEventPreview::Missing, Stored::preview))
        };
        let cooldown_key = format!("{}\n{key}", account.label);
        if !needs_refresh(&parsed.target, stored.as_ref(), unix_now_seconds())
            || self.public_event_refresh_cooling_down(&cooldown_key)
        {
            return Ok(current(stored.as_ref()));
        }

        let stored_event = stored
            .as_ref()
            .and_then(|stored| stored.row.event.as_deref());
        let (fetched, relays) = self
            .fetch_public_event_reference(&parsed, stored_event, discovery_indexers)
            .await;
        // One follow-up asks the verified author about deletions the first
        // query could not attribute, on every relay queried so far. If it does
        // not finish, nothing it should have covered is confirmed.
        let fetched = match fetched {
            Ok(mut fetched) => {
                let filters = follow_up_deletions(&parsed.target, stored_event, &fetched.events);
                if !filters.is_empty() {
                    match self
                        .relay_plane
                        .fetch_public_events(relays, filters, MAX_FETCHED_EVENTS)
                        .await
                    {
                        Ok(more) => fetched.merge(Fetched::new(more.events, more.complete)),
                        Err(_) => fetched.complete = false,
                    }
                }
                Ok(fetched)
            }
            Err(error) => Err(error),
        };
        // Start the cooldown only once a fetch finished, so a cancelled
        // refresh can be retried at once.
        self.start_public_event_refresh_cooldown(cooldown_key);
        let Ok(fetched) = fetched else {
            return Ok(current(stored.as_ref()));
        };
        if fetched.events.is_empty() && !fetched.complete {
            return Ok(current(stored.as_ref()));
        }

        let resources = self.resources.clone();
        let account = account.clone();
        let target = parsed.target;
        let preview = blocking_directory_task(move || {
            // The account may have been removed or replaced during the fetch.
            if resources.account_id_for_label(&account.label)? != account.account_id_hex {
                return Err(DirectoryError::from(StorageError::Backend(
                    "account changed during public event refresh".into(),
                )));
            }
            let cache = resources.cache_for_account(&account)?;
            let mut conn = cache.lock()?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Admission re-reads the row inside the write lock: a concurrent
            // refresh may have stored a newer version or a deletion.
            persist_refresh(
                &tx,
                &key,
                &target,
                &fetched.events,
                fetched.complete,
                unix_now_seconds(),
            )?;
            let preview = read_preview(&tx, &key)?;
            tx.commit()?;
            Ok(preview.unwrap_or(PublicEventPreview::Missing))
        })
        .await?;
        Ok(read(preview))
    }

    /// At most two safe reference hints, then the configured directory relays.
    pub(crate) fn public_event_query_relays(
        &self,
        hints: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        let hints = self
            .relay_plane
            .retain_safe_discovered_endpoints(hints, "public event hint");
        let mut relays = Vec::new();
        for relay in hints
            .into_iter()
            .take(MAX_HINT_RELAYS)
            .chain(self.directory_source_relays(&[]))
        {
            if relays.len() == MAX_QUERY_RELAYS {
                break;
            }
            if !relays.contains(&relay) {
                relays.push(relay);
            }
        }
        relays
    }

    /// The first query, then, only when it finished without the target, one
    /// supplementary query to the discovery indexers and the author's write
    /// relays. Returns the merged fetch and every relay queried, for the
    /// deletion follow-up.
    ///
    /// The merged fetch is complete only when every query it took was. A
    /// supplementary query that fails or stays partial never confirms absence,
    /// and neither does skipping an author route whose relay list could not be
    /// read in full.
    async fn fetch_public_event_reference(
        &self,
        parsed: &Reference,
        stored_event: Option<&Event>,
        discovery_indexers: &[TransportEndpoint],
    ) -> (Result<Fetched, String>, Vec<TransportEndpoint>) {
        let filters = parsed.target.filters(stored_event);
        let relays = self.public_event_query_relays(parsed.relay_hints.clone());
        let first = self
            .relay_plane
            .fetch_public_events(relays.clone(), filters.clone(), MAX_FETCHED_EVENTS)
            .await
            .map(|read| Fetched::new(read.events, read.complete));
        if first.as_ref().is_ok_and(|first| {
            first
                .events
                .iter()
                .any(|event| parsed.target.matches(event))
        }) {
            return (first, relays);
        }

        let (author_relays, author_route_complete) = self
            .public_event_author_relays(parsed.routing_author(), discovery_indexers)
            .await;
        let supplementary =
            self.public_event_supplementary_relays(&relays, discovery_indexers, author_relays);
        let mut queried = relays;
        let merged = if supplementary.is_empty() {
            first
        } else {
            let more = self
                .relay_plane
                .fetch_public_events(supplementary.clone(), filters, MAX_FETCHED_EVENTS)
                .await
                .map(|read| Fetched::new(read.events, read.complete));
            queried.extend(supplementary);
            match (first, more) {
                (Ok(mut first), Ok(more)) => {
                    first.merge(more);
                    Ok(first)
                }
                (Ok(mut only), Err(_)) | (Err(_), Ok(mut only)) => {
                    only.complete = false;
                    Ok(only)
                }
                (Err(error), Err(_)) => Err(error),
            }
        };
        let merged = merged.map(|mut merged| {
            merged.complete &= author_route_complete;
            merged
        });
        (merged, queried)
    }

    /// Safe NIP-65 write relays for `author`, and whether the relay list read
    /// finished. A cached list is used as it is; otherwise one kind-10002 read
    /// goes to the discovery indexers only. A failed or partial read skips the
    /// author route: it reports no relays and is not complete. Nothing read
    /// here is cached, and the inbox list (kind 10050) is never consulted.
    async fn public_event_author_relays(
        &self,
        author: Option<PublicKey>,
        discovery_indexers: &[TransportEndpoint],
    ) -> (Vec<TransportEndpoint>, bool) {
        let Some(author) = author else {
            return (Vec::new(), true);
        };
        // The cache read opens account caches and takes their SQLite locks, so
        // it runs on a blocking thread: lock contention must not park a Tokio
        // worker. A failed read is treated as uncached.
        let directory = self.clone();
        let author_hex = author.to_hex();
        let cached =
            blocking_directory_task(move || directory.cached_relay_list_status(&author_hex)).await;
        if let Ok(cached) = cached
            && cached.nip65.created_at > 0
        {
            return (
                self.safe_author_write_relays(cached.nip65.write_relays),
                true,
            );
        }
        let mut indexers = distinct_relays(
            self.relay_plane.retain_safe_discovered_endpoints(
                discovery_indexers.to_vec(),
                "public event indexer",
            ),
            &[],
        );
        indexers.truncate(MAX_SUPPLEMENTARY_RELAYS);
        if indexers.is_empty() {
            return (Vec::new(), true);
        }
        // `max_events` bounds the whole read, not each relay, and a read that
        // fills it counts as truncated. Room for every indexer's reply keeps
        // distinct current versions on different indexers from looking like a
        // partial read; a relay that ignores the limit still does.
        let max_events = indexers.len() * AUTHOR_RELAY_LIST_EVENTS_PER_INDEXER;
        let filter = Filter::new()
            .kind(Kind::RelayList)
            .author(author)
            .limit(AUTHOR_RELAY_LIST_EVENTS_PER_INDEXER);
        let read = self
            .relay_plane
            .fetch_public_events(indexers, vec![filter], max_events)
            .await;
        let read = match read {
            Ok(read) if read.complete => read,
            _ => return (Vec::new(), false),
        };
        let newest = read
            .events
            .iter()
            .filter(|event| event.kind == Kind::RelayList && event.pubkey == author)
            .max_by_key(|event| (event.created_at, std::cmp::Reverse(event.id)));
        let write_relays = newest
            .and_then(|event| NostrTransportEvent::from_nostr_event(event).ok())
            .and_then(|event| relay_list_state_from_event(&event))
            .map(|state| state.write_relays)
            .unwrap_or_default();
        (self.safe_author_write_relays(write_relays), true)
    }

    /// An author's write relays are their own published data: each one passes
    /// the discovered-endpoint safety rule, and one bad entry drops only itself.
    fn safe_author_write_relays(&self, relays: Vec<String>) -> Vec<TransportEndpoint> {
        self.relay_plane.retain_safe_discovered_endpoints(
            relays.into_iter().map(TransportEndpoint).collect(),
            "public event author write relay",
        )
    }

    /// The supplementary query's endpoints: every safe discovery indexer, then
    /// at most four author write relays in the room left, at most eight in
    /// all. Relays are compared by identity, not spelling, before either cap:
    /// a relay the first query already asked, or another spelling of one
    /// already chosen, never takes a slot.
    pub(crate) fn public_event_supplementary_relays(
        &self,
        queried: &[TransportEndpoint],
        discovery_indexers: &[TransportEndpoint],
        author_relays: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        let mut relays = distinct_relays(
            self.relay_plane.retain_safe_discovered_endpoints(
                discovery_indexers.to_vec(),
                "public event indexer",
            ),
            queried,
        );
        relays.truncate(MAX_SUPPLEMENTARY_RELAYS);
        let room = MAX_SUPPLEMENTARY_RELAYS - relays.len();
        let asked = queried.iter().chain(&relays).cloned().collect::<Vec<_>>();
        let author_relays = distinct_relays(
            self.relay_plane
                .retain_safe_discovered_endpoints(author_relays, "public event author write relay"),
            &asked,
        );
        relays.extend(
            author_relays
                .into_iter()
                .take(SEARCH_MAX_WRITE_RELAYS_PER_AUTHOR.min(room)),
        );
        relays
    }

    pub(crate) fn public_event_refresh_cooling_down(&self, key: &str) -> bool {
        self.state
            .public_event_refreshes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .is_some_and(|attempted| attempted.elapsed() < REFRESH_COOLDOWN)
    }

    pub(crate) fn start_public_event_refresh_cooldown(&self, key: String) {
        let mut attempts = self
            .state
            .public_event_refreshes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        attempts.retain(|_, attempted| attempted.elapsed() < REFRESH_COOLDOWN);
        if attempts.len() >= MAX_COOLDOWN_ENTRIES
            && let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, attempted)| **attempted)
                .map(|(key, _)| key.clone())
        {
            attempts.remove(&oldest);
        }
        attempts.insert(key, Instant::now());
    }
}

#[cfg(test)]
mod tests;
