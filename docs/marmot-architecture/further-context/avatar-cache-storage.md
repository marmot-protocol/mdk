---
title: "Avatar cache storage foundation"
created: 2026-09-16
updated: 2026-09-16
status: implementation
---

# Avatar cache storage foundation

C7-A/B of [#1554](https://github.com/marmot-protocol/mdk/issues/1554) adds protected local bytes to the existing
account SQLCipher store. [The Rust API](../../../crates/storage-sqlite/src/avatar_cache.rs) documents source
references, publication preconditions, status and removal. C7-B connects selected sources to validated downloads,
durable retry intent and background maintenance; C7-C still owns screen/native integration. Keep existing client caches until
that replacement is integrated and verified.

## Bounds and eviction

| Resource | Initial bound / policy |
| --- | --- |
| Encoded bytes | 128 MiB per account; at most 10 MiB per image |
| Owner mappings | 2,048, including missing entries |
| Image dimensions | Each dimension in `1..=4096`; formats PNG/JPEG/GIF/WebP |
| Recency | Durable sequence, updated by byte reads and binds; metadata status does not touch LRU |
| Timed freshness | Optional Unix-seconds deadline; stale bytes remain usable for the same source |

These are initial implementation defaults, not measured device optima. Eviction removes a mapping and its bytes,
fencing late completions with the old reference. Sharing across views uses the same owner; no cross-owner blob
sharing is introduced. Eviction must not itself requeue downloads: later acquisition must wait for fresh demand
or an applicable source update, avoiding refill/eviction loops. Retained attachments must not use this policy.

## Storage work and integrity

Local reads never await an engine, worker, relay or HTTP request. They are blocking database operations and must
be dispatched off the UI thread. Recency lives in a separate narrow table so widening its SQLite integer encoding
cannot rewrite image overflow pages. Unchanged source binds skip blob writes and usage aggregation; changed binds
and publications account over at most 2,048 rows. Checked counters fail rather than wrap.

The file-backed `avatar_recency_counter_widening_does_not_rewrite_blob_pages` regression first reproduced
21,572,352 WAL bytes for three reads of a 10 MiB image. With separate recency, three reads plus three unchanged
binds wrote 78,312 bytes on the development host. The test checks a bounded 256 KiB ceiling, not that exact count.
SQL-work coverage also bounds reads, unchanged binds and publication at capacity. Neither result measures mobile
first-frame latency. File allocation/reuse, total storage pressure and foreground lock latency still need device evidence.

`AvatarImage::new` enforces storage bounds only. Acquisition must authenticate encrypted data and validate fetched
image format/MIME/dimensions before publication. The stored checksum detects logical payload/record mismatches;
it is not a replacement for SQLCipher page authentication or image validation. Byte reads currently hash up to
10 MiB while holding the account connection. The C7-B optimized, file-backed SQLCipher host probe (20 warm reads per
size) measured p50/p95 of 0.79/2.42 ms at 256 KiB, 2.55/2.84 ms at 1 MiB and 36.95/38.76 ms at 10 MiB. These are total
local-read durations, including checksum/recency, not isolated SHA timings or device evidence. Keep verification for
now; C7-C bounds visible batches and retains client decoded caches. C9 must validate account-lock latency on flagship
devices before adoption. Read-time bounds protect the allocation/typed decoding boundary even though valid writes satisfy schema checks.

Account references retain explicit store-epoch scoping, consistent with other projection handles. Production does
not rotate `chat_presentation_meta.store_epoch` in place: account recreation gets a fresh store, and explicit cache
clear removes all mappings. The epoch-update trigger is a defensive database invariant, exercised directly by a test,
not an additional runtime reset mechanism. Existing terminal close, encrypted WAL and account-removal policies apply.

## Acquisition and maintenance (C7-B)

Migration 0078 adds versioned selected descriptors and retry state in the account SQLCipher store. Selected chat
presentation commits bind changed avatars and queue their acquisition in the same transaction, including pending
invitations. No failure selects a lower-priority group URL. A one-time upgrade ledger initializes existing chats in
batches of 64. It is consumed durably, so restart and unrelated title changes do not refill evicted entries.

`MarmotApp::request_identity_avatar` explicitly registers a conversation identity using local profile evidence.
Maintenance revisits at most 64 registered identities per batch after shared profile versions change, never historical
rosters. Unchanged directory versions skip the scan. C7-C supplies native visible-demand batches alongside the explicit
Rust request API. Placeholder registrations
can acquire a later profile picture. Profile versions reject stale maintenance, and eviction deletes registration;
local conversation deletion removes its chat/identity assets, and account cache clear drops registrations and unfinished
upgrade demand. Registrations are capped at 2,048.
The basic bind/read APIs still do not imply download demand.

After its existing startup path, the account worker wakes acquisition on presentation work signals, committed
presentation maintenance, media completion and the existing 15-second maintenance tick. Bounded bootstrap/identity
batches yield between passes. Empty bootstrap and no-due-job probes are read-only and acquire no write transaction.
Downloads reuse the four shared media permits, completion channel and worker-lifetime cancellation, while always
leaving one permit free for foreground media. Results hold capacity through publication. Each attempt
has a 60-second wall-clock ceiling and a 120-second durable lease, so a failed completion write cannot strand it
permanently. Metadata and
byte reads remain independent of that worker. A restart requeues interrupted attempts and rotates attempt tokens,
rejecting old completions. Source replacement, removal and eviction also delete the corresponding work. Account
close remains terminal; completion cannot reopen storage.

URL images are refresh-eligible after 24 hours. Encrypted content-addressed images have no periodic refresh. Transient
failures persist exponential backoff from 60 seconds to one hour, in addition to the HTTP helper's bounded attempt
budget. Integrity/decryption/image-admission failures also retry after backoff because the same URL or endpoint may
later serve the correct bytes. After 16 consecutive failures, retryable work slows to one probe per 24 hours; failed
probes retain that cadence until success or source replacement resets the budget. This avoids permanent loss after a
long outage without returning to hourly attempts against a broken source. Unsafe-source policy failures block until
source replacement. Same-source failures retain usable bytes.
Repeated visible demand raises priority but does not defeat retry deadlines or create duplicate fetches.

Fetches retain the existing public-address/DNS-pinning/redirect policy. Encrypted downloads verify the ciphertext
hash and authenticated decryption with a streaming ceiling of 10 MiB plus the 16-byte tag; URL downloads cap at
10 MiB. Both apply the existing PNG/JPEG/GIF/WebP header, declared encrypted MIME and dimension checks before atomic
publication. These checks do not assert that every animation frame fully decodes. Image decoding/rendering remains
client-owned. Malformed stored job envelopes become blocked so later jobs can progress.

`bind_avatar_source` and `publish_avatar` now use the existing nestable transaction helper. Callers must propagate
errors to the enclosing transaction; combined source/presentation and publication/job-state rollback tests cover
that composition. `read_avatar` still owns its read/recency transaction and must not be nested in a snapshot.

## C7-C screen and native access

Resolved chat rows, conversation headers and conversation identities carry optional `avatar_asset` metadata alongside
the existing selected descriptor. Placeholders have no asset. The metadata contains an opaque request `target`, an
optional byte `reference`, availability, acquisition state, content revision and encoded byte count. These are local
account/store and conversation-incarnation locators, not URLs, filesystem paths or authorization capabilities. Migration
0079 adds an index on the existing chat-row incarnation, so resolving a visible target does not scan the account chat list.

- Pass targets for **visible** images to `request_avatar_assets`. MDK revalidates the current source and registers
  demand without awaiting HTTP. This also restores an evicted visible image. It does not enumerate historical rosters
  or automatically register every identity in a potentially large sidecar.
- Call `read_avatar_assets` with returned references. It reads SQLCipher on the blocking pool, without engine hydration,
  account-worker startup, relay synchronization or an HTTP prerequisite. Ready and stale bytes are both usable.
- Both batches accept at most **16 items**. A byte read requires a budget of **1 byte through 16 MiB**; each image must
  fit in the remaining budget in full. Results preserve input order. `deferred` means usable bytes did not fit; retry
  that reference in a later batch with enough room. Metadata-only budget checks never load that BLOB or evict it.
- Key decoded pixels by **reference plus content revision**. The returned byte result is authoritative for its own
  revision. Missing and invalidated results contain no bytes; obtain a fresh target/reference from current screen
  metadata. A reference from a different account, reset store or replaced source cannot return old bytes.
- Existing chat-list and conversation window subscriptions deliver replacement metadata after committed acquisition,
  cache clear and local corruption repair. Receivers attach before the initial read; channel lag reloads current local
  state instead of replaying lossy individual transitions. No image bytes travel in subscription payloads.
- `clear_avatar_cache` removes local bytes and retained demand. Existing references invalidate. Background maintenance
  does not refill the cache; a later explicit visible request may do so. It does not remove message attachments.

Batches are bounded collections of independent per-asset operations, not a cross-asset transaction. Each returned
image/status pair is consistent; source changes between items can invalidate later references. If a request batch
fails after some registrations commit, retrying the batch is idempotent. Account removal and shutdown retain the
existing terminal-handle rules. Availability is evaluated at read time; hosts need not schedule freshness polling.

Swift and Kotlin use generated `AvatarAssetFfi` / `AvatarBytesFfi`; C mirrors both records and supplies matching list
free functions and commands. Regenerate bindings and link the matching library/header as one artifact cohort. No
version is bumped by this feature. Existing stateless image helpers remain available. Hosts should retain their
persistent image caches until this path is integrated and device-tested, and retain decoded/render caches afterward.
Host round trips and local SQL tests are not evidence of iOS/Android first-frame performance; C9 owns that handoff.
