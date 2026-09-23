---
title: "Audit delivery local slice: recorder evidence and design delta"
created: 2026-09-23
updated: 2026-09-23
status: local testable slice; no production activation
---

# Audit delivery local slice

This testable slice follows the simplified audit-delivery reassessment. Its
cursor has an internal version marker and does not adopt PR #1958's on-disk
layout.

## Recorder boundary evidence

The real `JsonlRecorder` tests show that each event is serialized once, written
as a newline-terminated v4 JSON row, and flushed before `record()` returns.
`flush()` is not `fsync`. A failed write is best effort: the row is absent,
the health counter rises, and a later row can be recorded. A failed flush
does not seal buffered bytes. An interrupted write can still leave a torn line.

At roughly 1 MiB, normal rotation renames the active file to a numbered
segment. The sealed file keeps its device/inode and all bytes; the new active
file has a new inode. Session and sequence continue, and only latest source
context is repeated in the new file. A crash after rename can leave a segment
without an active path. Restart appends a new `recorder_started` row to an
existing active file with a new session and sequence zero. Explicit destructive
`rotate()` replaces the active inode, discards its old bytes, starts a new
session, and replays source context. Tests cover these boundaries in
`audit/tests.rs` and `local_delivery.rs`.

## Local design delta

`LocalAuditDelivery` reads the recorder's actual active and numbered segment
files. It stores destination identity, monotonically assigned journal
generation, current segment name, device/inode, a 192-byte head fingerprint,
acknowledged byte offset, and at most one prepared range per journal. The
fingerprint catches accidental file replacement; it is not a full-file proof.
The prepared range is at most 96 complete lines and 64 KiB, with a SHA-256
digest of exactly those original bytes. The 64 KiB limit comfortably covers
the recorder's [documented ordinary rows](../../../crates/marmot-forensics/src/audit.rs)
(about 597 bytes on average, 811 bytes maximum in one measured session) while
bounding each read and retry. A line over
64 KiB becomes a visible gap; this is a local policy, not a schema limit.

Before publishing a prepared attempt, the reader syncs the source file because
the recorder only flushes. `prepare_once()` persists that bounded attempt and
returns an owned batch of the original JSONL lines plus a token; it retains no
source file handle or lock. The caller can release the account root lease before
an external send, then reacquire it for `finish(token, result)`. Both operations
reload the current cursor so a second owner cannot make a stale in-memory
completion valid. Cursor and gap updates use a private staged file, file sync,
rename, and parent directory sync. If publication is uncertain, the
instance fences further work. On restart, a prepared range is re-read and
compared with its range digest before the receiver sees it. `finish` rejects a
token whose destination, generation, or persisted range no longer matches. It
does not reopen the source: an explicit complete acceptance of the owned batch
can advance its cursor even if the source changed during the send. Retryable or
missing results keep the exact attempt for replay; permanent or partial results
block only that journal. A lost acceptance response can duplicate rows on retry,
so the eventual receiver must handle duplicate original rows.
An interrupted staging write is discarded on restart because the rename is
the commit point. If the first-byte fingerprint changes for a matching
device/inode, the reader retires the old generation, records an unknown-extent
missing-source gap for unaccepted bytes, and registers the current file as a
new generation. This also covers filesystem inode reuse after a destructive
clear. If a journal loses a previously observed, unprepared tail while keeping
the same inode and head, the reader likewise records an unknown-extent gap and
starts a new generation; it never replaces the old observed high-water mark
with the shorter length. A prepared-range digest mismatch records a bounded
gap before passing that range.

Gap records carry journal generation, segment, byte extent (or unknown end),
and a fixed reason. Complete malformed or oversized lines are skipped to their
next newline; a torn active tail waits; a torn sealed tail can be skipped.
Adjacent gaps with the same generation and reason are coalesced.
Changing a prepared range records a gap before passing its bytes. Destructive
clear of an unaccepted file records an unknown-extent missing-source gap. Gap
and blocked status are exposed to the caller. A source that moves between
discovery and reopening returns a retryable step for that journal; the next
discovery reconciles its segment and active names, including numbered segments.
Other journals can continue.

The fake receiver tests cover real recorder append, size rotation, restart,
retry, acceptance, changed range, active torn tail, malformed and oversized
lines, destructive clear, partial rejection, rotation during discovery and
between discovery and reopening, simulated inode reuse, and
observed unprepared tail truncation, corrupt or oversized cursor. The local
reader also tests restart after prepare, lost acknowledgement, duplicate-safe
retry, completion after source change, stale tokens, and absence of a retained
source descriptor in the returned batch. It has no HTTP, runtime scheduling,
root-lease acquisition, retention,
capacity cleanup, receiver validation, or investigation reader integration.
Those require the later receiver and lifecycle steps before production use.
