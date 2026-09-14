---
title: "Bounded live chat-list windows"
created: 2026-09-14
updated: 2026-09-14
status: implementation
---

# Bounded live chat-list windows

C4 M2 in [#1777](https://github.com/marmot-protocol/mdk/issues/1777) adds
`MarmotAppRuntime::open_chat_list_window(account, view, initial_rows)` over the
storage navigation introduced by M1. It reuses durable chat rows and selected
presentation. It adds no migration or second conversation store.

## Ownership and delivery

A handle belongs to one account, account-store lifetime, and `ChatListView`:
Chats, Unread, Archived or Left. Open attaches runtime and presentation
invalidations before reading the initial window. The new path never opens the
legacy full-list subscription or performs its readiness/full-list read.

One actor serializes commands and refreshes. The initial response and subsequent
notifications are complete `ChatListWindowSnapshot` replacements, identified by
a random subscription generation and increasing sequence. A slow consumer receives
the latest replacement; skipped sequences are normal. Clients should ignore any
response older than their installed generation/sequence. A command supplies the
sequence it acts on; an outdated command receives `StaleWindow`.

`window_handle()` is independently cloneable so paging and anchor commands work
while `recv()` waits. Once queued, a command outlives cancellation of its caller;
its completion remains available in the update stream. Dropping the subscription
closes its actor even when command handles survive. Runtime shutdown or account
cache eviction (including sign-out, wipe and setup reset) closes existing handles.
Reopen returns a new generation. Cursors are ephemeral boundaries, not restart tokens.

## Window policy

- Default initial size: 50 rows. Initial and paging requests: 1–100 rows.
- Retained window: at most 200 rows. Paging grows it to that cap, then slides it.
- The client reports a visible stable group identity and keeps its pixel offset.
  At the top, incoming activity remains visible normally. `return_to_top` is explicit.
- Refresh resolves the anchor in the current ordering. If it disappears, choose
  the next surviving prior neighbor, then the previous; otherwise reset to top/empty.
  Responses report the chosen anchor and its current index.
- Eviction never removes the visible anchor. At the cap a page request can stop
  advancing if its anchor would otherwise be evicted; the client reports its new
  viewport anchor before continuing. `has_more_before/after` describes the list,
  not whether an unchanged protected viewport can advance.

Every refresh and page command reads a fresh contiguous window, resolving both
sides and selections under one account database snapshot. It does not append a
page to rows from an older ordering. M1's conservative account navigation revision
can change under unrelated traffic; recovery seeks directly around retained keys
rather than traversing from the top. Boundary-only revision changes do not redraw
an unchanged window or reject otherwise current client commands; the next delivered
replacement carries current boundaries. SQL and row conversion work are bounded by
the requested window and at most 200 fallback identities.

Render titles and avatars from each row's **`presentation`**. This contains the
selected peer/group identity and fallback tokens for client localization; clients
must not rebuild
those decisions from `row.name`, `row.avatar`, `row.member_count`, or
`row.conversation_kind`. Those legacy metadata fields are retained for compatibility
and can lag source updates; they are not the window's display contract. The selected
presentation is maintained from current group/profile inputs independently of the
legacy full-list stale flag.

## Preparation, failures and lifecycle policy

Missing selected values are prepared only for the requested window using local
cached evidence and the existing compare-and-store protection. Other selected
backfill continues in the existing bounded account maintenance worker. Ready reads
do not hydrate history or MLS groups or wait for the network. If legacy **base**
chat rows are still missing, their ordering is not yet known. Each read initializes
one bounded base-row batch locally, even without an account worker. Initial open
retries preparation after yielding until those rows are ready, or the caller cancels,
the account resets, or the runtime shuts down. Other initial read errors are returned.
This one-time base initialization can scale with an imported account and its retained
history; it never presents a misleading partial/empty list. Subsequent read failures
remain explicit and retry inside the actor. This is distinct from unrelated
selected-presentation work, which does not block an otherwise ready window.

Invalidations are coalesced before a read. Those arriving during the read remain
queued for the next refresh. Lag refreshes the current window. Local read/preparation
failures surface explicitly and retain a one-second retry obligation without
requiring a new event. Internal query/cursor validation errors are terminal and retain
their error classification. Losing a teardown signal closes the window conservatively:
account cache eviction can preserve both account ID and durable store epoch, so a
refresh alone cannot establish that its lifetime survived. Timed mute expiry
refreshes only the retained window.

Pending invitations and Left rows have effective unread/mention/manual-attention
fields suppressed in this API; raw stored read intent and lower-level APIs remain
unchanged. Acceptance preserves archive. Successful self-arrival from Left/Removed
atomically restores membership and archive eligibility and updates the account
worker's in-memory intent. Consented rejoin restores once; replay cannot undo a
subsequent explicit archive. Existing membership push-share side effects remain.

M3 owns independent account attention summaries; M4 provides the
[native binding contracts and consumer handoff](chat-projections-native.md). Full-dataset search and custom folders keep their existing
APIs until separately migrated. These row-count and SQL-work tests do not establish
native rendering speed or a byte-size bound for arbitrary preview payloads.
