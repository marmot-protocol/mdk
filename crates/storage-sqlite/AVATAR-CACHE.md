# Local avatar storage

C7-A of [#1554](https://github.com/marmot-protocol/mdk/issues/1554) adds the storage foundation.
It does not yet connect downloads, maintain selected screen sources, or expose native bindings.
Those are C7-B and C7-C; clients should keep their existing image-loading paths until that handoff.

## Ownership and reads

`SqliteAccountStorage` keeps encoded avatar bytes and metadata in the existing account SQLCipher
file. Account close remains terminal for every clone; no new file, key, runtime or worker exists.
The migration provisions an empty cache without reading chat history or modifying presentation epochs.

An application-owned **owner key** identifies a logical chat or identity. The **source key** identifies
its selected descriptor, using existing material-sensitive presentation key derivation. Use the same
owner across screens for shared access; this slice deliberately does not deduplicate blobs across
owners. Do not put raw URLs or serialized decryption material in these keys.

- `bind_avatar_source(owner, source)` preserves the reference for the same source and atomically
  replaces it (erasing old bytes) for a different source. A placeholder/removal uses
  `remove_avatar_source(reference)`; stale cleanup cannot erase a newer generation.
- `avatar_reference(owner)` and `avatar_status(reference, now)` read metadata without creating
  demand, touching LRU or fetching anything.
- `read_avatar(reference, now)` returns bounded local bytes plus status and content revision.
  Ready/stale hits update LRU. The call never invokes an engine, account worker, relay or HTTP path.
  This is blocking database I/O; native callers must run it off the UI thread.
- A reference binds a random source-generation token to the existing account store epoch. It is
  not an authorization grant. Replacing/removing/evicting an owner makes old references invalid.
  Clearing the cache or rotating the store epoch invalidates all prior references and publications.

Availability distinguishes missing, ready, stale-but-usable and invalidated. `refresh_at` is an
optional Unix-seconds deadline: reaching it does not delete bytes. Encrypted immutable assets can
use `None`; the URL refresh policy and acquisition/error states will be supplied by C7-B.

## Publication and validation

Capture `content_revision` before acquiring bytes. `publish_avatar(reference, expected_revision,
image, refresh_at)` atomically compares the source/store generation and content revision, updates
bytes/metadata and evicts as necessary. A superseded result changes nothing. Every successful
publication advances the revision, including a same-URL refresh. Decoded-image caches must key on
both the reference and content revision.

`AvatarImage::new` enforces encoded-byte and dimension bounds, but **does not decode an image or
verify encryption**. Its caller must validate fetched format/MIME/dimensions, enforce safe network
policy, and authenticate encrypted images before publication. C7-B must establish that boundary
before downloads can feed this store. Storage persists a SHA-256 digest and checks it on local byte
reads; a mismatch discards the corrupt payload, advances the revision to fence in-flight work and
returns a repairable miss. A metadata-only status is not a byte-integrity check.

Failed transactions roll back publication and every eviction together. A failed download does not
call publication and therefore leaves the prior usable image intact. Logical source selection,
background work, coalescing, retry intent and notifying consumers about changes/evictions remain
app responsibilities in C7-B/C. Storage methods alone do not observe profile/group changes.

## Bounds and lifecycle

The initial fixed limits are 128 MiB encoded bytes, 2,048 owner mappings (including misses), 10 MiB
per image, and dimensions in `1..=4096`. Eviction deletes least-recently-used mappings and their
bytes, preserving the mapping being bound/published. Explicit byte reads and binds affect recency;
rendering metadata for a whole chat list does not keep every image artificially hot. Each read is
indexed by one token; mutation accounting scans at most the bounded cache metadata, not chat history.

Eviction does not itself requeue a download. Acquisition must wait for fresh demand or an applicable
source update, so bounded maintenance cannot endlessly refill just-evicted assets. Metadata lookup
of an evicted owner returns no reference; reading its old reference returns invalidated. A new bind
creates a missing entry with a new generation, rejecting delayed pre-eviction completions.

`clear_avatar_cache` removes all mappings/bytes in the selected account. Account deletion/reset
must continue using the existing account lifecycle; switching accounts must not erase the previous
account's cache. Source and content revisions are checked within the same transaction as publication,
and checked integer counters fail rather than wrap/reuse generations.

Limits bound logical content, not physical SQLite/WAL size. Existing encrypted WAL, secure-delete,
checkpoint and terminal-close policies apply. Files may retain allocated pages for reuse. Disk-growth,
space-pressure and foreground lock latency measurements remain part of the runtime/device handoff.
Attachment retention is separate: do not put retained message media in this evictable cache.

## Verification

`cargo test -p storage-sqlite avatar_ --lib` covers migration, encrypted reopen and restrictive files,
source replacement/ABA, account epochs and close, stale/local hits, compare-and-publish races,
corruption repair, bounded eviction, rollback after partial eviction and integer overflow. SQL-work
coverage compares a local read at one entry and at the 2,048-entry capacity. These are storage tests,
not claims about device first-frame rendering or background transfer behavior.
