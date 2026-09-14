---
title: "Revision-safe conversation drafts"
created: 2026-09-14
updated: 2026-09-14
status: implementation
---

# Revision-safe conversation drafts

C5 M2 ([#1838](https://github.com/marmot-protocol/mdk/issues/1838)) adds selected composer metadata and
revision-checked save, clear, attachment reads, and send commands. It extends the existing encrypted draft store
and outgoing queue; it does not add a second composer or payload owner. Legacy draft APIs remain available.

## Selected state

`selected_message_draft` reads one group's text, reply target, attachment metadata and revision in one deferred
SQLite snapshot. Attachment metadata includes size, dimensions, thumbnail hash, duration and waveform; it does
not load attachment plaintext. `message_draft_attachment_if_revision` loads only the requested attachment's bytes.
The query cost depends on the selected draft and its metadata, not other conversations or attachment BLOB sizes.
It does not impose a new bound on text or metadata size.

Migration 0073 preserves existing drafts and seeds group revision rows. A durable account-wide counter advances
for draft and attachment mutations, including legacy writes and same-timestamp edits. Tokens bind the database's
store epoch, group and counter. Delete/recreate cannot reuse a token; counter exhaustion fails the write. Tokens
are opaque Rust values, with no serialization or native wire contract yet. Copying a database copies its scope.

Conditional save/clear rejects a stale token with `MessageDraftRevisionConflict` without changing the draft.
Malformed input remains a separate error; absent groups consistently return `UnknownGroup` at the app boundary. A successful mutation returns a fresh
selected snapshot. Empty composers still have revisions, so an old empty snapshot cannot overwrite a later draft.

## Send acceptance and recovery

`send_message_draft` captures the requested revision's text and reply target. For media, the caller supplies
already-prepared references in selected attachment order, using the existing upload path. Each reference must match
that position's filename and media type. This catches metadata/order mismatches, not different bytes with identical
metadata: callers must still prepare from the selected revision's bytes and submit that original revision. Missing
references, stale revisions, and invalid media policy/epoch inputs fail before acceptance. M2 does not upload media.

The command stages a binding between the revision and the exact outgoing event/hash. That binding retains no
payload bytes and is **not acceptance**. The existing queued intent or application fanout write consumes it and
clears only the matching draft revision in the same SQLite transaction. Savepoints also protect callers that catch
an inner write error and later commit their outer transaction. A newer composer survives acceptance of an older
submission. There is at most one binding per group; the account session serializes sends.

Before acceptance, an error or cancellation leaves the draft. After acceptance, the existing outgoing message owns
retry and failure state, and cancellation or restart cannot revive the submitted composer. The legacy send result
can still report a later delivery error after durable acceptance: callers must reload selected state and use the
outgoing message's retry state, rather than restoring the composer just because the send returned an error.
Dropping a direct client send cancels its exact revision/event binding best-effort; an older event cannot unbind a
replacement staged against the same draft revision. A command already enqueued on an account
worker continues under that worker even if its waiting caller disappears, as with other runtime send commands.

## Changes and composition

App save/clear and legacy mutations emit post-commit draft wakeups. Acceptance installs its observer on the actual
engine writer, which uses a separate SQLite handle from app projection reads, and emits after the durable handoff
but before waiting on relay delivery. The observer carries only account/group routing information; consumers reload
the durable revision. Nested acceptance defers its wakeup until the owning transaction commits; rollback, panic
and failed commit discard pending wakeups. Callbacks run after releasing transaction ownership. The raw broadcast receiver may lag; subscribe-before-read and reload-on-lag are required. M4 will
integrate this with live conversation window reset/eviction handling. M5 owns native bindings.

## Validation

Storage tests cover migration preservation/rollback, legacy and conditional mutations, attachment-only revisions,
stale/cross-store tokens, delete/recreate, counter exhaustion, read-only queries, keyed bytes, nested handoff failure,
outer rollback, SQLCipher reopen, queued acceptance and replay. VM-step comparisons use 200 versus 20,000 unrelated
drafts and 1 KiB versus 8 MiB selected attachment bytes. App tests exercise a relay barrier to verify acceptance and
notification before network completion, cancellation, edits during submission, validated media replies, typed
conflicts, missing groups and runtime command forwarding.
These establish storage and lifecycle behavior; they are not native device latency measurements.
