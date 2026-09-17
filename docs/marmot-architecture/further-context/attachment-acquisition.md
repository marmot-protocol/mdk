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
only the storage discovery foundation below is implemented by this slice.

## Problem and existing foundation

Opening a conversation should find already acquired attachment bytes locally.
Today MDK retains decryption secrets and can explicitly download an attachment,
but does not own a durable background attachment queue or retained byte store.
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
rebuild or rescan history. This migration adds no bytes or transfer jobs. C8-B is
the immediate next planned PR after C8-A; this storage slice has no native callers.

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

## Decision before runtime/native discovery

Audit client Photos/Videos/Files tab requirements before C8-B. Opaque slots keep
protocol classification in the shared app parser. Do not scan unlimited pages to
fill a filtered tab: either expose bounded scanned pages with explicit continuation,
or add a parser-owned classification index if the contract requires full typed
pages. Storage must not invent a second MIME/voice-note parser.

## Decisions before acquisition implementation

- Specify per-file/aggregate admission and disk-pressure behavior without silently
  evicting successfully acquired retained bytes; pausing new acquisition is the
  proposed default, not yet an implemented policy.
- Define durable partial-download/range-resume support, retry scheduling and
  protected partial-file cleanup. Current whole-body verification does not make
  partially downloaded plaintext safe to expose.
- Define shared-reference erasure, cancellation/publication races, account teardown
  and explicit remove/download-again APIs. Retention deadlines must be rechecked
  before publication; discovery follows authoritative source pruning.

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
