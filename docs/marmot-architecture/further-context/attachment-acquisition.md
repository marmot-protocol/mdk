---
title: "Attachment discovery and acquisition"
created: 2026-09-17
updated: 2026-09-17
tags: [marmot, attachments, projections]
status: implementation-plan
---

# C8: attachment discovery, acquisition and local access

Tracking: [projection plan #1742](https://github.com/marmot-protocol/mdk/issues/1742).
Source audit: master `ebb884b8` (MDK 0.10.1). This is an implementation plan;
C8-A storage discovery and C8-B runtime/native discovery are implemented. C8-C1
adds the durable storage foundation below; worker acquisition and native retained-byte
access remain later slices.

## Problem and existing foundation

Opening a conversation should find already acquired attachment bytes locally.
Today MDK retains decryption secrets and can explicitly download an attachment,
and C8-C1 now supplies durable jobs and protected byte storage. The runtime does
not yet feed or execute those jobs automatically.
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

Migration 82 adds source-bound demand, leases, retry deadlines and protected bytes
inside each account's SQLCipher database. It creates no transfer jobs on upgrade.
The caller supplies a shared-parser-validated slot and its exact plaintext digest;
a mismatched digest is a caller bug to fix by re-parsing, not a download failure to
retry. Storage does not implement a second imeta parser. Admission compares that
exact source against the current index. Unknown source epochs, pending
invitations, hidden and expired sources are not admitted. No engine or network is
needed to inspect job state or read retained bytes.

A claimed attempt has a private store/attempt fence. Publication rechecks the
current source, invitation acceptance, expiry and unexpired lease, then verifies
the plaintext digest and atomically commits the bytes and ready state. The future
worker must still authenticate/decrypt the entire body using the existing media
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

This is a storage API, not automatic download, partial/range-resume support, transfer
progress or a native binding. Next connect accepted canonical demand to the existing
bounded media worker, including shutdown cancellation, retry pacing and maintenance;
then expose native availability, local bytes and explicit removal/download-again.
[#1437](https://github.com/marmot-protocol/mdk/issues/1437) remains open across those slices.

## Decisions before worker integration

- Choose the runtime payload-byte budget and filesystem headroom policy. Storage
  already refuses over-budget publication without eviction; the worker must stop
  admitting work under pressure rather than repeatedly downloading rejected bytes.
- Define durable partial-download/range-resume support, retry scheduling and
  protected partial-file cleanup. Current whole-body verification does not make
  partially downloaded plaintext safe to expose.
- Wire source/account teardown and cancellation into the worker, and expose the
  existing storage removal/download-again operations through native APIs. Test
  runtime publication races on top of the storage source/lease/expiry fences.

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
