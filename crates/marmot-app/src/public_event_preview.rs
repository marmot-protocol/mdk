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
//!   either form: an `e` tag deletes that exact event, an `a` tag deletes every
//!   version of the coordinate up to its own `created_at`. A row keeps the
//!   newest deletion time it has seen (`deleted_through`), even while it shows
//!   a newer version, so a relay that kept an older version cannot restore it.
//!   Rows that carry a deletion time are evicted last.
//! - Not-found results and fetch failures are never stored. A fetch where a
//!   relay did not complete may admit what it found, but never confirms a row,
//!   and an event-ID row it admits is rechecked after 30 minutes.
//! - Complete event-ID rows never refetch. Coordinate rows refetch after
//!   30 minutes. Any finished refresh starts a 30-second in-memory cooldown
//!   per key.
//!
//! Author profiles are not part of a preview; hosts read them through the
//! cached-identity API and refresh them through the directory.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cgka_traits::TransportEndpoint;
use cgka_traits::storage::StorageError;
use marmot_account::AccountSummary;
use nostr::event::Event;
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip19::{FromBech32, Nip19};
use nostr::prelude::{EventId, Filter, Kind, PublicKey, RelayUrl};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{AppError, MarmotApp, blocking_app_task, unix_now_seconds};

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
const MAX_FETCHED_EVENTS: usize = 64;
/// Limit on the unattributed kind-5 query for an event ID. A full answer may
/// hide the author's deletion behind other keys' requests.
const EVENT_DELETION_QUERY_LIMIT: usize = 16;

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
        }),
        Nip19::Event(event) => Some(Reference {
            target: Target::EventId(event.event_id),
            relay_hints: hints(&event.relays),
        }),
        Nip19::Coordinate(naddr) => {
            let kind = naddr.coordinate.kind;
            let supported = kind.is_addressable()
                || (is_replaceable(kind) && naddr.coordinate.identifier.is_empty());
            supported.then(|| Reference {
                target: Target::Coordinate(naddr.coordinate.clone()),
                relay_hints: hints(&naddr.relays),
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

/// The author to ask again when an event-ID lookup's unattributed kind-5
/// query came back full without that author's deletion: requests signed by
/// other keys may have crowded it out.
fn crowded_deletion_author(
    id: &EventId,
    stored: Option<&Event>,
    fetched: &[Event],
) -> Option<PublicKey> {
    let author = fetched
        .iter()
        .find(|event| event.id == *id)
        .or(stored)?
        .pubkey;
    let id = id.to_hex();
    let deletions = fetched
        .iter()
        .filter(|event| event.kind == Kind::EventDeletion && has_tag(event, "e", &id))
        .collect::<Vec<_>>();
    (deletions.len() >= EVENT_DELETION_QUERY_LIMIT
        && !deletions.iter().any(|deletion| deletion.pubkey == author))
    .then_some(author)
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

/// The row a refresh leads to, or `None` when nothing is known.
fn admit(target: &Target, stored: Option<&Row>, fetched: &[Event]) -> Option<Row> {
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
            if stored.is_some_and(|row| row.event.is_none()) {
                return stored.cloned();
            }
            let event = candidates.into_iter().next()?;
            Some(match deletion_time(event, &deletions) {
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
            // An `e` deletion of one version hides it and every older version.
            for event in &candidates {
                if deletion_time(event, &deletions).is_some() {
                    deleted_through = deleted_through.max(Some(event.created_at.as_secs()));
                }
            }
            let shown = candidates
                .into_iter()
                .filter(|event| {
                    deleted_through.is_none_or(|through| event.created_at.as_secs() > through)
                })
                .fold(None::<&Event>, |best, event| match best {
                    Some(current) if !supersedes(event, current) => Some(current),
                    _ => Some(event),
                });
            (shown.is_some() || deleted_through.is_some()).then(|| Row {
                event: shown.map(|event| Box::new(event.clone())),
                deleted_through,
            })
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

fn corrupt_row() -> AppError {
    StorageError::Serialization("invalid cached public event".into()).into()
}

fn read_row(conn: &Connection, key: &str) -> Result<Option<Stored>, AppError> {
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
fn read_preview(conn: &Connection, key: &str) -> Result<Option<PublicEventPreview>, AppError> {
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
) -> Result<(), AppError> {
    let stored = read_row(conn, key)?;
    let Some(row) = admit(target, stored.as_ref().map(|stored| &stored.row), fetched) else {
        return Ok(());
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
    trim(conn)
}

fn write_row(
    conn: &Connection,
    key: &str,
    row: &Row,
    complete: bool,
    now: u64,
) -> Result<(), AppError> {
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
/// deletion time first.
fn trim(conn: &Connection) -> Result<(), AppError> {
    let (mut count, mut total): (i64, i64) = conn.query_row(
        "SELECT count(*), coalesce(sum(bytes), 0) FROM public_event_previews",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count <= MAX_ENTRIES && total <= MAX_TOTAL_BYTES {
        return Ok(());
    }
    let mut statement = conn.prepare(
        "SELECT cache_key, bytes FROM public_event_previews
         ORDER BY deleted_through IS NOT NULL, touched_at, cache_key",
    )?;
    let mut rows = statement.query([])?;
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

fn invalid_batch(len: usize) -> AppError {
    AppError::InvalidPublicEventReferences(format!(
        "requested {len} references; maximum is {MAX_PUBLIC_EVENT_REFERENCES}"
    ))
}

impl MarmotApp {
    /// Network-free cached previews, one per reference in input order.
    /// Unparseable references are `Unsupported` rows, not errors.
    pub(crate) fn cached_public_event_previews(
        &self,
        account: &AccountSummary,
        references: &[String],
    ) -> Result<Vec<PublicEventPreviewRead>, AppError> {
        if references.len() > MAX_PUBLIC_EVENT_REFERENCES {
            return Err(invalid_batch(references.len()));
        }
        let keys = references
            .iter()
            .map(|reference| parse_reference(reference).map(|parsed| parsed.target.cache_key()))
            .collect::<Vec<_>>();
        let mut found = HashMap::new();
        if keys.iter().any(Option::is_some) {
            let cache = self.directory_cache_for_account(account)?;
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
    pub(crate) async fn resolve_public_event_preview(
        &self,
        account: &AccountSummary,
        reference: &str,
    ) -> Result<PublicEventPreviewRead, AppError> {
        let read = |preview| PublicEventPreviewRead {
            reference: reference.to_owned(),
            preview,
        };
        let Some(parsed) = parse_reference(reference) else {
            return Ok(read(PublicEventPreview::Unsupported));
        };
        let key = parsed.target.cache_key();
        let stored = {
            let app = self.clone();
            let account = account.clone();
            let key = key.clone();
            blocking_app_task(move || {
                let cache = app.directory_cache_for_account(&account)?;
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
        let relays = self.public_event_query_relays(parsed.relay_hints);
        let fetched = self
            .relay_plane
            .fetch_public_events(
                relays.clone(),
                parsed.target.filters(stored_event),
                MAX_FETCHED_EVENTS,
            )
            .await;
        let fetched = match (fetched, &parsed.target) {
            (Ok(mut fetched), Target::EventId(id)) => {
                if let Some(author) = crowded_deletion_author(id, stored_event, &fetched.events) {
                    let filter = Filter::new()
                        .kind(Kind::EventDeletion)
                        .author(author)
                        .event(*id)
                        .limit(4);
                    match self
                        .relay_plane
                        .fetch_public_events(relays, vec![filter], MAX_FETCHED_EVENTS)
                        .await
                    {
                        Ok(more) => {
                            fetched.events.extend(more.events);
                            fetched.complete &= more.complete;
                        }
                        Err(_) => fetched.complete = false,
                    }
                }
                Ok(fetched)
            }
            (fetched, _) => fetched,
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

        let app = self.clone();
        let account = account.clone();
        let target = parsed.target;
        let preview = blocking_app_task(move || {
            // The account may have been removed or replaced during the fetch.
            if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex
            {
                return Err(AppError::from(StorageError::Backend(
                    "account changed during public event refresh".into(),
                )));
            }
            let cache = app.directory_cache_for_account(&account)?;
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
    fn public_event_query_relays(&self, hints: Vec<TransportEndpoint>) -> Vec<TransportEndpoint> {
        let hints = self.retain_safe_discovered_endpoints(hints, "public event hint");
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

    fn public_event_refresh_cooling_down(&self, key: &str) -> bool {
        self.public_event_refreshes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .is_some_and(|attempted| attempted.elapsed() < REFRESH_COOLDOWN)
    }

    fn start_public_event_refresh_cooldown(&self, key: String) {
        let mut attempts = self
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
#[path = "public_event_preview/tests.rs"]
mod tests;
