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
//!   coordinate; relay hints are only query inputs.
//! - A coordinate keeps the newest version: higher `created_at`, then the
//!   lower event ID (NIP-01).
//! - An author-signed NIP-09 request seen during a refresh replaces the row
//!   with a deletion marker, so a relay that kept the event cannot restore it.
//!   A coordinate marker is lifted only by a version newer than the deletion.
//! - Not-found results and fetch failures are never stored.
//! - Event-ID rows never refetch. Coordinate rows refetch after 30 minutes.
//!   Any completed refresh starts a 30-second in-memory cooldown per key.
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
const COORDINATE_REFRESH_SECONDS: u64 = 30 * 60;
const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_COOLDOWN_ENTRIES: usize = 256;
/// Reads refresh `touched_at` at most this often, so most reads write nothing.
const TOUCH_INTERVAL_SECONDS: u64 = 60 * 60;
const MAX_HINT_RELAYS: usize = 2;
const MAX_QUERY_RELAYS: usize = 6;
const MAX_FETCHED_EVENTS: usize = 64;

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
    author_hint: Option<PublicKey>,
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
            author_hint: None,
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
            author_hint: None,
            relay_hints: Vec::new(),
        }),
        Nip19::Event(event) => Some(Reference {
            target: Target::EventId(event.event_id),
            author_hint: event.author,
            relay_hints: hints(&event.relays),
        }),
        Nip19::Coordinate(naddr) => {
            let kind = naddr.coordinate.kind;
            let supported = kind.is_addressable()
                || (is_replaceable(kind) && naddr.coordinate.identifier.is_empty());
            supported.then(|| Reference {
                target: Target::Coordinate(naddr.coordinate.clone()),
                author_hint: Some(naddr.coordinate.public_key),
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

    /// Whether `deletion` is a NIP-09 request by `author` covering this target.
    fn deleted_by(&self, deletion: &Event, author: &PublicKey) -> bool {
        if deletion.kind != Kind::EventDeletion || deletion.pubkey != *author {
            return false;
        }
        match self {
            Self::EventId(id) => has_tag(deletion, "e", &id.to_hex()),
            Self::Coordinate(coordinate) => has_tag(deletion, "a", &coordinate.to_string()),
        }
    }

    fn filters(&self, author: Option<PublicKey>) -> Vec<Filter> {
        match self {
            Self::EventId(id) => {
                let mut deletions = Filter::new().kind(Kind::EventDeletion).event(*id).limit(8);
                if let Some(author) = author {
                    deletions = deletions.author(author);
                }
                vec![Filter::new().id(*id).limit(1), deletions]
            }
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
                    Filter::new()
                        .kind(Kind::EventDeletion)
                        .author(coordinate.public_key)
                        .coordinate(coordinate)
                        .limit(4),
                ]
            }
        }
    }
}

/// What the cache holds for one key.
#[derive(Clone, Debug)]
enum Stored {
    Present {
        event: Box<Event>,
        fetched_at: u64,
    },
    /// `created_at` is the deletion's timestamp.
    Deleted {
        created_at: u64,
        fetched_at: u64,
    },
}

impl Stored {
    fn fetched_at(&self) -> u64 {
        match self {
            Self::Present { fetched_at, .. } | Self::Deleted { fetched_at, .. } => *fetched_at,
        }
    }

    fn preview(&self) -> PublicEventPreview {
        match self {
            Self::Present { event, fetched_at } => PublicEventPreview::Present {
                event_json: event.as_json(),
                fetched_at: *fetched_at,
            },
            Self::Deleted { .. } => PublicEventPreview::Deleted,
        }
    }
}

/// The row a refresh writes, if any.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Keep,
    /// The stored row still holds; record that a relay was just asked.
    Confirm,
    Present(Box<Event>),
    Deleted {
        created_at: u64,
        deletion_id: EventId,
    },
}

/// Decide what a refresh stores, given the current row and verified events.
fn admit(target: &Target, stored: Option<&Stored>, fetched: &[Event]) -> Admission {
    let stored_event = match stored {
        Some(Stored::Present { event, .. }) => Some(event.as_ref()),
        _ => None,
    };
    let best = fetched
        .iter()
        .filter(|event| target.matches(event) && event.as_json().len() <= MAX_EVENT_BYTES)
        .chain(stored_event)
        .fold(None::<&Event>, |best, event| match best {
            Some(current) if !supersedes(event, current) => Some(current),
            _ => Some(event),
        });
    let author = match target {
        Target::EventId(_) => best.map(|event| event.pubkey),
        Target::Coordinate(coordinate) => Some(coordinate.public_key),
    };
    let deletion = author.and_then(|author| {
        fetched
            .iter()
            .filter(|event| target.deleted_by(event, &author))
            .max_by_key(|event| event.created_at)
    });

    match target {
        Target::EventId(_) => {
            if matches!(stored, Some(Stored::Deleted { .. })) {
                return Admission::Keep;
            }
            match (deletion, best) {
                (Some(deletion), _) => Admission::Deleted {
                    created_at: deletion.created_at.as_secs(),
                    deletion_id: deletion.id,
                },
                (None, Some(event)) => Admission::Present(Box::new(event.clone())),
                (None, None) => Admission::Keep,
            }
        }
        Target::Coordinate(_) => {
            // NIP-09: an `a` deletion removes every version up to its own
            // `created_at`; a later version is valid again.
            let stored_deleted_through = match stored {
                Some(Stored::Deleted { created_at, .. }) => Some(*created_at),
                _ => None,
            };
            let fetched_deleted_through = deletion.map(|event| event.created_at.as_secs());
            let deleted_through = stored_deleted_through.max(fetched_deleted_through);
            match best {
                Some(event)
                    if deleted_through
                        .is_none_or(|through| event.created_at.as_secs() > through) =>
                {
                    Admission::Present(Box::new(event.clone()))
                }
                _ => match (deletion, deleted_through) {
                    (Some(deletion), Some(through)) if Some(through) == fetched_deleted_through => {
                        Admission::Deleted {
                            created_at: through,
                            deletion_id: deletion.id,
                        }
                    }
                    (_, Some(_)) => Admission::Confirm,
                    _ => Admission::Keep,
                },
            }
        }
    }
}

fn needs_refresh(target: &Target, stored: Option<&Stored>, now: u64) -> bool {
    match (target, stored) {
        (_, None) => true,
        (Target::EventId(_), Some(_)) => false,
        (Target::Coordinate(_), Some(stored)) => {
            stored
                .fetched_at()
                .saturating_add(COORDINATE_REFRESH_SECONDS)
                <= now
        }
    }
}

fn corrupt_row() -> AppError {
    StorageError::Serialization("invalid cached public event".into()).into()
}

fn read_row(conn: &Connection, key: &str) -> Result<Option<Stored>, AppError> {
    let row = conn
        .query_row(
            "SELECT event_json, created_at, deleted, fetched_at
             FROM public_event_previews WHERE cache_key = ?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((event_json, created_at, deleted, fetched_at)) = row else {
        return Ok(None);
    };
    let fetched_at = u64::try_from(fetched_at).map_err(|_| corrupt_row())?;
    if deleted {
        let created_at = u64::try_from(created_at).map_err(|_| corrupt_row())?;
        return Ok(Some(Stored::Deleted {
            created_at,
            fetched_at,
        }));
    }
    let event = Event::from_json(event_json.ok_or_else(corrupt_row)?).map_err(|_| corrupt_row())?;
    Ok(Some(Stored::Present {
        event: Box::new(event),
        fetched_at,
    }))
}

/// The host-facing state of one row, without parsing its stored event.
fn read_preview(conn: &Connection, key: &str) -> Result<Option<PublicEventPreview>, AppError> {
    let row = conn
        .query_row(
            "SELECT event_json, deleted, fetched_at FROM public_event_previews
             WHERE cache_key = ?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((event_json, deleted, fetched_at)) = row else {
        return Ok(None);
    };
    if deleted {
        return Ok(Some(PublicEventPreview::Deleted));
    }
    Ok(Some(PublicEventPreview::Present {
        event_json: event_json.ok_or_else(corrupt_row)?,
        fetched_at: u64::try_from(fetched_at).map_err(|_| corrupt_row())?,
    }))
}

fn i64_secs(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Apply `admission` and trim the cache, inside the caller's transaction.
fn write_admission(
    conn: &Connection,
    key: &str,
    admission: Admission,
    now: u64,
) -> Result<(), AppError> {
    let (event_json, created_at, event_id, deleted) = match admission {
        Admission::Keep => return Ok(()),
        Admission::Confirm => {
            conn.execute(
                "UPDATE public_event_previews SET fetched_at = ?2, touched_at = ?2
                 WHERE cache_key = ?1",
                params![key, i64_secs(now)],
            )?;
            return Ok(());
        }
        Admission::Present(event) => (
            Some(event.as_json()),
            event.created_at.as_secs(),
            event.id,
            false,
        ),
        Admission::Deleted {
            created_at,
            deletion_id,
        } => (None, created_at, deletion_id, true),
    };
    let bytes = ROW_OVERHEAD_BYTES
        + i64::try_from(key.len() + event_json.as_ref().map_or(0, String::len)).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO public_event_previews
            (cache_key, event_json, created_at, event_id_hex, deleted, bytes, fetched_at, touched_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT(cache_key) DO UPDATE SET
            event_json = excluded.event_json,
            created_at = excluded.created_at,
            event_id_hex = excluded.event_id_hex,
            deleted = excluded.deleted,
            bytes = excluded.bytes,
            fetched_at = excluded.fetched_at,
            touched_at = excluded.touched_at",
        params![
            key,
            event_json,
            i64_secs(created_at),
            event_id.to_hex(),
            deleted,
            bytes,
            i64_secs(now),
        ],
    )?;
    trim(conn)
}

/// Evict least recently used rows until both budgets hold.
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
        "SELECT cache_key, bytes FROM public_event_previews ORDER BY touched_at, cache_key",
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

        let author = parsed.author_hint.or(match &stored {
            Some(Stored::Present { event, .. }) => Some(event.pubkey),
            _ => None,
        });
        let fetched = self
            .relay_plane
            .fetch_public_events(
                self.public_event_query_relays(parsed.relay_hints),
                parsed.target.filters(author),
                MAX_FETCHED_EVENTS,
            )
            .await;
        // Start the cooldown only once a fetch finished, so a cancelled
        // refresh can be retried at once.
        self.start_public_event_refresh_cooldown(cooldown_key);
        let Ok(fetched) = fetched else {
            return Ok(current(stored.as_ref()));
        };

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
            // Re-read inside the write lock: a concurrent refresh may have
            // stored a newer version or a deletion marker.
            let stored = read_row(&tx, &key)?;
            let admission = admit(&target, stored.as_ref(), &fetched);
            write_admission(&tx, &key, admission, unix_now_seconds())?;
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
