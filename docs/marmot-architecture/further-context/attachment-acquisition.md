---
title: "Attachment discovery and acquisition"
created: 2026-09-17
updated: 2026-09-18
tags: [marmot, attachments, projections]
status: implementation-plan
---

# C8: attachment discovery, acquisition and local access

Tracking: [projection plan #1742](https://github.com/marmot-protocol/mdk/issues/1742).
Source audit: master `ebb884b8` (MDK 0.10.1). This is an implementation plan;
C8-A storage discovery and C8-B runtime/native discovery are implemented. C8-C1
adds the durable storage foundation below. C8-C2 connects automatic worker acquisition;
C8-C3 adds protected partial/range resume; native retained-byte access (C8-D) remains separate.

## Problem and existing foundation

Opening a conversation should find already acquired attachment bytes locally.
Today MDK retains decryption secrets and can explicitly download an attachment,
and C8-C1 supplies durable jobs and protected byte storage. C8-C2 feeds and executes
those jobs automatically in explicitly enabled, non-frozen account workers.
C8-D2 enables acquisition by default with native local access, durable controls and policy.
A timeline window covers only a bounded part of a conversation. The synchronous
`list_media` compatibility API instead scans raw app events, potentially without
a limit, and does not provide authoritative removal or pagination semantics.

| Existing owner | Reuse / gap |
| --- | --- |
| `marmot-app/src/media/mod.rs` | Strict ordered attachment outcomes, structural validation, transport selection, full-body AEAD and plaintext hash verification. Rejected slots retain their index. Download returns transient bytes. |
| `marmot-app/src/client/mod.rs` | Prepares downloads using retained source-epoch secrets and group policy; warms secrets. Keep this policy boundary. |
| `marmot-app/src/runtime/account_worker.rs` | Existing bounded media admission and cancellable HTTP work. Extend it; do not create a competing download pool. |
| `storage-sqlite/src/encrypted_media_secrets.rs` | Durable account-scoped secrets, reference tracking and retirement watermarks. Reuse source-deletion/pruning lifecycle. |
| `storage-sqlite/src/timeline.rs` | Canonical source order, deletion/invalidation and secure retention pruning. Authoritative source for attachment discovery. |
| `marmot-uniffi/src/commands/media.rs` | Explicit async download, synchronous legacy `list_media`; no durable acquisition/local-byte handoff. |
| Avatar cache (C7) | Useful account isolation, opaque local-access and shutdown patterns. Its LRU eviction policy is unsuitable for retained attachments. |

## Independently mergeable sequence

1. **C8-A: storage discovery** (part of [#1448](https://github.com/marmot-protocol/mdk/issues/1448)).
   Index delivered, canonical chat attachment slots in the account database;
   provide bounded newest-first pages and revision-fenced cursors. Deletion,
   invalidation, blocking and source replacement update the index transactionally.
   Preserve legacy delivered entries without epochs and malformed attachment slots;
   the app parser remains responsible for typed readiness/rejection.
2. **C8-B: runtime/native discovery** (finish #1448). Apply the shared parser and
   expose asynchronous account/group-scoped pages, revisions and typed restart
   outcomes through the app/native boundaries. Preserve legacy `list_media` until
   callers migrate. Verify complete traversal and removal through bindings.
3. **C8-C: protected retention and durable acquisition** (coordinate
   [#1437](https://github.com/marmot-protocol/mdk/issues/1437)). Persist demand,
   retry state, suppression after explicit removal and protected acquired bytes;
   reconcile source eligibility before publishing results. Resume work after
   runtime restart. Reuse merged retry/deadline work (#1811 / #1829).
4. **C8-D: local access and progress** (complete the relevant #1437 scope).
   Native clients receive bounded local-byte access, availability and transfer
   progress. Explicit download-again clears removal suppression. Validate
   cancellation, restart, failure, disk pressure and account isolation.

C8-A/B are discovery, not permission to download. Automatic attachment acquisition
waits for invitation acceptance; avatars may be acquired before acceptance.
Retained history remains available after leaving a group. Retain secrets and
acquired bytes until source deletion/expiry or explicit local removal. Ordinary
history refresh, repair and restart must not undo explicit removal.

The storage migration backfills the derived index once from the existing materialized
timeline. Subsequent source writes maintain it incrementally; page reads do not
rebuild or rescan history. This migration adds no bytes or transfer jobs. C8-B
exposes the index through async runtime/UniFFI methods and the equivalent blocking C ABI.
Native APIs are available; released-artifact adoption remains C9 work.

## Discovery refresh and restart contract

Version equality detects new attachments as well as destructive changes.
`requires_restart_since` distinguishes additions-only refresh from a mandatory
restart: new attachments keep existing cursors usable, including under continuous
incoming traffic. New rows below a cursor can appear on subsequent pages; rows
above an already passed boundary require a separate refresh. This is pagination
over a changing collection, not a fixed snapshot.

Deletion, invalidation, source replacement/reordering, visibility changes and
account/group generation changes require callers to discard loaded pages and
restart. Materialized visibility follows the canonical timeline view; parity tests
cover blocking, invitation changes and retained history after group-list removal.

## Runtime/native contract and client audit

C8-B adds `attachment_history_page(account, group, limit, cursor)` and
`attachment_history_version(account, group)`. SQL, account resolution and parser
work run off the async caller thread, without engine hydration or relay readiness.
Swift/Kotlin receive opaque process-local cursor/version objects; the C ABI mirrors
them with explicit ownership. See [native handoff](../../../crates/marmot-uniffi/ATTACHMENT-HISTORY.md).

Client source inspected on 2026-09-17 (these audited files were clean):

- iOS `e05d6a05`: `SharedMediaLibraryView.swift` loads `listMedia` once;
  `SharedMediaLibraryPresentation.swift` filters visual, audio and file categories.
  URL links have a separate bounded timeline scan.
- Android `3af73352`: `ui/medialibrary/MediaLibrary.kt` derives Images, Videos,
  Voice, Files and URLs tabs from loaded media/timeline records.

The contract returns at most 100 original attachment slots, with a shared-parser
accepted/rejected outcome and MDK category (image, video, audio, file or rejected).
Audio classification does not assert voice-note intent (#1252). Apps filter within
loaded pages and request bounded continuation; an empty filtered page is not proof
of exhaustion while `has_more` is true. Rejected slots consume the page limit and
preserve their original album index. There are no filtered totals or full-category
page guarantees, no hidden scan-until-full loop, and no additional MIME index.
Links remain outside this attachment projection. Preserve legacy `list_media` until
clients adopt paging and distinguish partially loaded tabs from truly empty tabs.

## C8-C1: durable storage foundation

Migration 83 adds source-bound demand, leases, retry deadlines and protected bytes
inside each account's SQLCipher database. It creates no transfer jobs on upgrade.
The caller supplies a shared-parser-validated slot and its exact plaintext digest;
a mismatched digest is a caller bug to fix by re-parsing, not a download failure to
retry. Storage does not implement a second imeta parser. Admission compares that
exact source against the current index. Unknown source epochs, pending
invitations, hidden and expired sources are not admitted. No engine or network is
needed to inspect job state or read retained bytes.

A claimed attempt has a private store/attempt fence. Publication rechecks the
current source, invitation acceptance, expiry and unexpired lease, then verifies
the plaintext digest and atomically commits the bytes and ready state. The
worker authenticates/decrypts the entire body using the existing media
pipeline before publication. Interrupted leases become due again after reopen;
ordinary repeated demand cannot reset retry deadlines or replace ready bytes.
Claim-time policy ineligibility parks work separately from an explicit-retry
failure. Successful re-admission requeues only parked jobs. Worker integration
must re-admit affected canonical sources after acceptance/unblocking/rejoin and
on startup; a due-only sweep cannot discover policy changes.

Bytes have no LRU. Publication enforces a caller-supplied account payload-byte
budget and a 512 MiB storage ceiling per object; the existing stricter transport
ciphertext cap remains in force (also 512 MiB, including AEAD overhead). Capacity refusal preserves existing objects and
requires the caller to pause/retry. Filesystem free-space and WAL overhead admission
belong to worker integration. Publication still binds the complete verified
plaintext and SQLite can copy it; worker admission must account for that peak
memory cost. Local storage reads return at most 1 MiB and recheck
source visibility/expiry. Stored job status alone is not authorization to read.
Due/expiry maintenance pages contain at most 64 entries and use dedicated indexes.

Jobs and removal tombstones belong to raw source events. Deletion/expiry and
source invalidation erase retained bytes; matching timeline repair preserves them.
Explicit local removal cancels the job and survives restart, repair and later
source revalidation. Only explicit download-again clears that suppression while
the source remains retained. Already acquired left-group history remains readable.
Separate copies per slot avoid cross-message erasure ambiguity in this first slice.
Account-store generation reset invalidates all handles and clears retained state.

## C8-C2: automatic worker acquisition

Migration 84 queues retained eligible attachment slots once at upgrade. Source changes,
acceptance, unblocking, repair and group recreation enqueue changed slots transactionally.
The worker consumes at most 32 descriptors per turn, uses the shared strict parser for
both the reference and plaintext digest, and acknowledges each queue generation only
after admission or rejection. Repeated account saves do not rescan/requeue history.
Explicit-removal suppression, ready bytes, backoff and terminal failures survive rediscovery.

Automatic work uses the existing cancellable media executor. A FIFO semaphore permits
one automatic transfer across all accounts in a runtime; each account has at most one
pending permit request. A permit remains held through queued plaintext publication.
At least one of the four per-account media slots is reserved for foreground work.
Preparation reads projected group policy and retained source-epoch secrets; it never
hydrates MLS state. Missing secrets wait for sync's existing secret-warming path.
Invitation acceptance and canonical visibility are checked again at claim/publication.

Starting Rust-configurable resource defaults (`AttachmentAcquisitionPolicy::default()`):

| Policy | Default |
| --- | --- |
| Retained plaintext per account | 2 GiB, no eviction |
| Free disk reserve | 256 MiB, plus four admission-sized objects for SQLite/WAL overhead |
| Automatic ciphertext ceiling | 64 MiB, enforced during streaming, including chunked bodies |
| Concurrent automatic transfers | One across accounts in a runtime |

`MarmotAppConfig::attachment_acquisition` defaults to `Some(default_policy)`. Rust callers may
supply `None` to disable the fallback. Durable per-account policy overrides that fallback;
native hosts can read and set it without starting the runtime. Frozen/NSE runtimes skip acquisition. Explicit
downloads retain their 512 MiB ciphertext cap. Admission reserves the configured automatic
transfer limit (64 MiB by default) against quota, including explicit queued requests whose
references have no declared size. This avoids requiring 512 MiB of unused quota for tiny
explicit files. Checkpoint and publication checks enforce actual quota and disk use as files
grow; a final remainder below the admission reservation can still stay unused.
Unknown free space fails closed. These are resource limits, not an OS background-execution
entitlement or mobile throughput evidence.

Network failures back off durably from 15 seconds to one hour. New durable ciphertext
checkpoint progress resets the failure streak; replaying an existing prefix does not. Unavailable local
policy/secrets defer one candidate for 15 seconds before claiming it; no transfer attempt
is consumed and due siblings keep their deadlines. Integrity/decryption failures,
publication digest mismatches and over-limit responses require explicit retry;
locator failover still runs, and a remaining transient candidate keeps the attempt retryable.
Automatic transfers use three-minute leases around a two-minute transfer deadline.
Explicit queued transfers retain the 15-minute media deadline with a 20-minute lease.
A running automatic attempt promoted to explicit keeps its current deadline; subsequent
attempts use the explicit policy.
A 30-second body-idle deadline releases stalled transfers; explicit legacy downloads retain their existing deadline.
Worker exit cancels active HTTP and releases permits. Before scheduling any transfer,
a new exclusive account worker reclaims abandoned fetching attempts in batches of 64;
old completions remain fenced, and existing retry deadlines/ready bytes are unchanged.
Expired leases remain a fallback for interruption recovery.
Ready bytes are SQLCipher-protected and source/lease/expiry-fenced; no automatic LRU applies.

C8-C2 introduced complete-body retries. C8-C3 below preserves compatible partial transfers.
C8-D1 exposes native availability/local bytes; C8-D2 exposes progress and explicit controls.
Automatic acquisition now defaults on. Native removal/policy controls, shorter transfer/idle deadlines,
recent-message priority, size-limit re-admission and policy validation are implemented and covered by regressions.
The legacy download API continues returning transient bytes until clients adopt that contract.
[#1437](https://github.com/marmot-protocol/mdk/issues/1437) stays open across those slices.

## C8-C3: protected partial downloads and Range resume

Migration 85 stores ciphertext chunks and bounded validator metadata in the same SQLCipher
account store. It creates no transfers on upgrade. Checkpoints append at an exact offset,
in chunks of at most 1 MiB; every append rechecks the store/attempt, retained source,
acceptance, expiry and combined retained-plus-reserved payload budget. Filesystem reserve
is checked off the account worker before each checkpoint. No plaintext partial is stored
or exposed. A cancelled transfer may lose its last uncommitted chunk; completed checkpoints
survive process death and the existing startup attempt reclamation.

The representation is bound to the admitted source, ciphertext digest, exact URL digest,
strong ETag and known total length. Raw URLs are not duplicated in partial metadata.
Resume sends `Range` and `If-Range` through the existing address-pinned, redirect-vetted
HTTP path, with identity encoding. A `206` must describe the exact remaining suffix and
same strong validator/total. A `200` starts a replacement body; the old checkpoint survives
until a replacement checkpoint or final publication. Changed/missing validators, unusable
ranges (including unknown totals), or a `416` discard the incompatible prefix and retry
once from zero. Repeated invalid ranges, unsupported encoding and over-limit bodies fail closed. Servers without
a strong ETag or known length still support complete downloads without durable checkpoints.
Validator comparison follows [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-range);
Last-Modified-only resume is deliberately not implemented.

Each locator has its own validator scope; failover never combines a prefix from a different
URL even when its ETag string matches. Candidate failure cleanup is fenced by ciphertext
and final response URL (including redirects), so a bad alternative server cannot erase an
unused prefix from another locator. Retryable redirect failures preserve valid checkpoints.
Chunks carry local SHA-256 checksums to detect damaged checkpoint contents. The normal complete ciphertext hash, AEAD authentication and plaintext
hash checks remain mandatory before publication. A ciphertext hash miss on a body containing
saved checkpoint bytes discards that checkpoint and schedules a clean download on the durable
retry path. A fresh full-download hash miss remains terminal. The regression
`attachment_resume_hash_miss_retries_from_zero_after_reopen` covers both outcomes across
store reopen, including a fully saved checkpoint. Resume still assembles a bounded full body
for the existing crypto pipeline; it does not add streaming plaintext decryption.

The first checkpoint reserves the complete declared ciphertext size against the same account
budget as retained plaintext. Worker admission, append and publication share this accounting;
existing prefixes can finish when reservations fill the budget. New demand pauses without
spending transfer attempts. Atomic publication replaces its own reservation while preserving
other jobs' allocations. Complete small responses skip the final checkpoint write. No retained-byte eviction is introduced. Success, terminal/parked state,
source removal/invalidation, explicit removal and store reset delete partials transactionally.
Expired message jobs cascade to their partials. Abandoned checkpoints expire 24 hours after
last progress, reclaimed in indexed batches of 64 by non-frozen worker maintenance, including
when acquisition is disabled. Disabling acquisition does not erase already acquired bytes.
This temporary checkpoint lifetime does not change the agreed retained-media lifetime.

Tests cover interrupted HTTP plus encrypted reopen and verified publication, task cancellation,
Range ignored, changed/weak validators, malformed ranges, ciphertext corruption, over-limit
responses, locator failover, bounded quota/rollback, chunk corruption and lifecycle fences.
C8-D1 local-byte access is described below; C8-D2 adds the control and progress contract.

## Issue audit and exclusions

The open issue/PR inventory was refreshed on 2026-09-17 and direct attachment,
transfer and retention candidates were inspected. No competing open media PR was
identified by title. This is a scope/overlap audit, not reproduction of every issue.

- #1448 owns discovery; #1437 owns resumable transfer/progress. Keep those identities.
- #927 (duration/waveform/size hints) and #1252 (explicit voice-note intent) are
  coordinated metadata work, not prerequisites to discovering or retaining bytes.
- #1355 (negotiated size beyond the current cap), #1327 (view-once), #1688 (relay
  expiration vs local retention) and #859 (media replies) remain separate contracts.
- #1226 is downstream decrypted-file lifecycle; #1229 is agent export-directory
  safety. Neither substitutes for the MDK byte store.
- #819 account-removal cleanup and #1796 secret-warming cost are adjacent lifecycle
  concerns to recheck during acquisition; this slice does not claim to fix them.

C9 still owns released-artifact adoption and device evidence. Storage tests do not
establish download throughput, native rendering speed or mobile background survival.

## C8-D1: local native attachment access

`attachment_local_assets(account, group, targets)` resolves at most 64 original
message/source/index tuples to current readable retained assets. Results preserve
input order and duplicates; a missing reference means only that local bytes are
unavailable. It neither enqueues demand nor reports download progress. The metadata
query uses indexed source lookup and SQLite BLOB length, never materializing payloads.

`read_attachment_asset(account, reference, offset, limit)` reads at most 1 MiB through
incremental SQLite BLOB access. Each read rechecks the store generation, current source
visibility and retention deadline. A true/empty result means EOF, including empty files;
unavailable means discard any assembled host result. Retained history after leaving
remains readable. Explicit removal, source replacement/deletion/expiry and account reset
invalidate old references. Bytes must have passed complete ciphertext/AEAD/plaintext
verification at publication; partial checkpoints are never reachable here.

These async Rust/UniFFI methods run account/store work on the blocking pool without
an account worker, hydration, secret warming or network fallback. C wrappers are
blocking; call them off the UI thread. Existing `download_media` is unchanged and
still returns transient complete downloads. Hosts must reacquire metadata after runtime
reconstruction and keep their existing caches until release/device adoption is validated.
See [native usage and lifetime contract](../../../crates/marmot-uniffi/ATTACHMENT-ACCESS.md).

`attachment_local_access_is_bounded_offline_and_survives_reopen` covers chunk boundaries,
offline reconstruction, cross-account handles, retained-left history and local removal.
`attachment_local_metadata_is_read_only_and_follows_byte_visibility` covers no-demand
lookup, exact source selection and immediate retention expiry before maintenance.
## C8-D2: progress, controls and default acquisition

Migration 86 extends the existing acquisition rows with durable cancellation, explicit-request
intent, size-policy failure reasons and progress generations. It adds a per-account policy override;
there is no second download queue. Cancellation invalidates the attempt immediately, survives restart,
and retains valid partial ciphertext under its existing 24-hour expiry. It never erases ready bytes.
Remove deletes local bytes and suppresses automatic reacquisition until an explicit download-again.

Disabling automatic work invalidates active automatic leases, pauses queued automatic demand and
preserves explicit requests and cached bytes. Re-enabling never clears cancellation/removal.
Native snapshot and subscription targets are bounded to 64 original slots. Replacement snapshots
are coalesced to at most four per second; they include states, a transfer generation, received/known
total ciphertext bytes, optional retry time and an opaque job reference. Verification phases precede
Ready; only verified plaintext is exposed by local byte reads. Claim advances the generation
and clears counters before HTTP starts; a later body restart or locator fallback advances it
again. The first body belongs to the claimed generation. Metadata write failures cannot mask
integrity failures. Progress notifications do not wake the cancellation monitor; a separate
control signal interrupts it immediately, with a one-second fallback for cross-writer changes.
Snapshots use a deferred read transaction and load store identity once per frame. Active
subscriptions keep a one-second fallback. Idle/terminal subscriptions refresh at most every
30 seconds, or at their next known retention expiry if earlier; control and presentation
notifications wake them promptly. Cross-writer changes without a notification may take up
to 30 seconds to appear while idle. Every byte read still revalidates source/expiry immediately.

Explicit requests precede automatic work, and recent incoming sources precede older backfill.
Candidate queries seek the due range before sorting eligible jobs by priority, so future
backoff and active leases are not scanned. The explicit-only path also seeks past disabled
automatic work. Priority sorting still visits currently eligible jobs; this is not a claim
of constant work for an arbitrarily large due backlog.
The global one-transfer permit uses FIFO account admission. Transfer/idle deadlines prevent a
stalled server retaining that slot indefinitely. Raising the automatic cap readmits size-policy
failures, while integrity failures still require explicit retry. Invalid zero/over-ceiling policy
values, including a quota smaller than the admission reservation, are rejected before mutation,
and invalid Rust policy is rejected at runtime start. Disk reserves may intentionally exceed
current free space; resource pressure is exposed as RetryScheduled with a retry time, without
spending a transfer attempt or evicting existing bytes.

Release/binding publication, app cache adoption and device benchmarks remain C9. Local tests do
not establish mobile throughput or background execution entitlement. See the native usage guide.
