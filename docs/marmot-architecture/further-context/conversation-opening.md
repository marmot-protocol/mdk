---
title: "Bounded conversation opening"
created: 2026-09-14
updated: 2026-09-15
status: implementation
---

# Bounded conversation opening

C5 M1 ([#1838](https://github.com/marmot-protocol/mdk/issues/1838)) adds
`SqliteAccountStorage::conversation_open`: one read-only snapshot containing a bounded timeline page,
retained read state, invitation status, the selected opening position and an opaque anchor for each row.
It reuses the existing timeline and unread projections without a schema migration. This is the storage foundation;
the composed live screen and native bindings follow in later C5 slices.

## Opening and recovery

- `Automatic` opens around the first unread message in an accepted conversation, otherwise at the latest row.
  Pending invitations open at latest while retaining raw unread state for acceptance. Manual unread alone does not
  invent a message anchor. Archived and departed conversations keep their retained history accessible.
- `Latest` explicitly selects the tail. `Message(id)` selects a retained identity, returning `MessageNotFound` if
  absent rather than silently jumping to latest.
- `Anchor(token)` follows the same identity if its canonical position changes. If the row was physically removed,
  it selects the next canonical row relative to the saved position, then the previous row, then an empty window.
  Deleted and invalidated timeline rows remain retained tombstones and can still be anchors.

The default total budget is 50 rows, with a valid range of 1–200. The target is included in that budget. Around a
target, the query initially reserves half the context for older rows and fills unused space from the other side.
Results are in ascending canonical order with exact `has_more_before` and `has_more_after` flags. Canonical order
uses the existing source epoch/phase/time/identity key, not timestamp alone. Reply previews use the existing bounded
hydration path. The limit bounds row count and SQL work, not the total bytes of message content.

Tokens are opaque Rust values scoped to a database's durable store epoch and a group. They survive reopening the
same database while held by the caller; they have no serialization or cross-process/native wire contract yet.
Copying a database also copies its scope identity. A different store or group returns `AnchorScopeMismatch`.

## Consistency and ownership

All reads share one deferred SQLite transaction. A caller's existing transaction stays caller-owned, including on
error. Opening never marks messages read, changes manual unread, prepares projections, loads the roster, or starts
network work. Closed storage remains closed.

The read requires the group's unread membership to be prepared, without pending dirty message entries, and aligned
with its durable read marker and chat-list summary. `ReadStateNotReady` asks the existing projection owner to prepare
or refresh that group before retrying. It does not trigger a history scan on the opening path. Raw unread counters
are deliberately distinct from C4 account attention: each active unarchived pending invitation adds one
attention-only item, while archived and departed/departing conversations contribute nothing. Invitation
message/mention counts remain suppressed until acceptance; the Unread filtered list still excludes invitations.

## Inputs to later screen composition

The compact header should combine keyed group lifecycle state (pending, accepted, leaving/departed and reason),
the existing selected title/avatar presentation and its revision, member count, local membership/role, and the
inputs needed to derive send/invite/settings capabilities. It must not require a complete roster or `groups()` scan.
[#1793](https://github.com/marmot-protocol/mdk/issues/1793) owns the existing keyed group/header read gap; M1 does
not duplicate that work. C5 M3 will define the shared Rust header/capability DTO and include identities needed by
the visible messages and their reply previews. Localization remains client-owned.

C5 M2 adds revision-safe draft metadata, M3 composes presentation, M4 owns live window updates/retry consistency,
and M5 exposes native bindings. Media acquisition and cache policy remain separate C7/C8 work.

## Validation

Storage regressions cover canonical opening, every page edge, pending acceptance, manual unread, terminal history,
physical anchor removal, reordered optimistic messages, tombstones, dirty preparation, read-only/nested rollback,
store/group scope, closed handles, and SQLCipher reopen. A second WAL connection changes history and read state
during an open to verify that the result remains one snapshot. SQLite VM-step checks compare 200 and 20,000
messages with unrelated groups/events present, including deep and physically missing anchors. These are storage
work bounds, not device latency or full-screen performance claims.
