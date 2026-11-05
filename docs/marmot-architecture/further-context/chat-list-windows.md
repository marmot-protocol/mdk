---
title: "Bounded live chat-list windows"
created: 2026-09-14
updated: 2026-11-05
status: implementation
---

# Bounded live chat-list windows

C4 M2 in [#1777](https://github.com/marmot-protocol/mdk/issues/1777) adds
`MarmotAppRuntime::open_chat_list_window(account, view, initial_rows)` over the
storage navigation introduced by M1. It reuses durable chat rows and selected
presentation. It adds no migration or second conversation store.

## Ownership and delivery

A handle belongs to one account, account-store lifetime, and chat-list query: a
`ChatListView` (Chats, Unread, Archived or Left) optionally narrowed by a filter
(see [Queries](#queries)). Open attaches runtime and presentation
invalidations before reading the initial window. The new path never opens the
legacy full-list subscription or performs its readiness/full-list read.

One actor serializes commands and refreshes. The initial response and subsequent
notifications are complete `ChatListWindowSnapshot` replacements, identified by
a random subscription generation and increasing sequence. A slow consumer receives
the latest replacement; skipped sequences are normal. Clients should ignore any
response older than their installed generation/sequence. A command supplies the
sequence it acts on and applies to the current retained viewport. Background
replacements (preview, badge, order or membership changes) do not supersede a
sequence, so paging keeps working under steady account activity. A command
receives `StaleWindow` when it quotes a sequence not yet published, or one older
than the first replacement showing another command's viewport move, or when
`set_visible_anchor` quotes an older sequence whose row a background replacement
dropped. The same miss against the current sequence is `AnchorOutsideWindow`.

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
unchanged. The separate account attention summary counts each active unarchived
invitation once without treating its messages as unread. Acceptance preserves archive. Successful self-arrival from Left/Removed
atomically restores membership and archive eligibility and updates the account
worker's in-memory intent. Consented rejoin restores once; replay cannot undo a
subsequent explicit archive. Existing membership push-share side effects remain.

## Queries

A chat-list query ([#2983](https://github.com/marmot-protocol/mdk/issues/2983)) is
a base view plus an optional filter: `All`, `Any` and `Not` over leaf conditions.
In Rust it is the `ChatListViewQuery` tree; a `ChatListView` converts into the
unfiltered query, so the four views are the predefined queries and fixed-view
calls are unchanged. UniFFI and C carry the filter as a flat node list: node 0 is
the root, and every other node is the child of exactly one node listed before it,
which makes the list acyclic with a single root by construction.
`ChatListFilter::from_nodes` checks that shape (child in range, after its parent,
not shared, every node reachable). UniFFI uses the node list too, so both bindings
share one shape.

Leaves are the facts the chat list already stores, each matching what the
presented row shows: scope (active, archived, left, pending invitation); unread,
manual unread and mention, which never match invitations or Left chats because
their badges are hidden; pinned; pending leave and disbanding; a draft with
non-blank text or an attachment; a last message showing a pending or failed send
(an older unresolved send behind newer history does not count, as the row does
not show it); and a group ID list. Folder rules are ordinary filters: "excluded IDs always win" is
`All[Not(GroupIds(excluded)), Any[GroupIds(included), rule]]`, and an included ID
never adds a chat outside the base view. An empty `All` matches every chat in the
view and an empty `Any` none. Kind, mute, chat text, message text and people are
later slices of #2983.

A query has at most 8 levels, 64 nodes and 500 group IDs in all. Over a bound, or
with a malformed node list, every consumer fails with `InvalidChatListQuery`
before reading; host group IDs are normalized like any other host group ID.

The filter compiles to SQL appended to the view's condition, ahead of keyset
paging, with every value bound as a parameter. Reads still walk the view's page
index in display order; each leaf is a `chat_list_rows` column or one keyed
lookup per chat (account groups, engine leave and disband records, and the draft
tables). Cost grows with the chats in the view, never with history. Cursors
belong to the exact query that produced them.

Filtered results are consistent within one read: each window read, `chat_list_ids`
and `revalidate_chat_list_ids`. Only fixed-view cursors continue across reads;
storage refuses a cursor with a filter (`FilteredCursorUnsupported`) up front,
because the navigation revision that makes cursors stale covers the views'
inputs, not drafts, manual unread, mentions, delivery state, invitations or
leave and disband records. Cross-read filtered paging would need revision
triggers on each of those inputs, a follow-up only if a host needs it. Windows
never page with stored cursors, so they are unaffected.

Windows re-read on almost every account change already. Drafts are the exception:
a draft change wakes a window only when the chat is visible, unless the window's
filter tests drafts, in which case any draft change in the account re-reads it.

## Select all

A window holds at most 200 rows, so hosts must not derive "select all" or a bulk
action's count from it. `chat_list_ids(account, query)` returns every ID the query
matches in display order from one read, through the same compiled condition the
window pages through; its cost grows with the view's chats, never with history.
While base rows are pending it returns `ChatPresentationNotReady`, never a partial
set, after repairing one bounded batch as a window read does.
`revalidate_chat_list_ids(account, query, ids)` returns the still-matching subset
in the caller's order with duplicates dropped, and never adds chats that matched
since. The bindings name the query forms `open_chat_list_query_window`,
`chat_list_query_ids` and `revalidate_chat_list_query_ids`; the fixed-view forms
remain.

Both calls are stateless. The host keeps checkbox state, revalidates right before a
bulk action, then calls the existing per-chat commands, which check their own
preconditions.

M3 owns independent account attention summaries; M4 provides the
[native binding contracts and consumer handoff](chat-projections-native.md). Full-dataset search and custom folders keep their existing
APIs until separately migrated. These row-count and SQL-work tests do not establish
native rendering speed or a byte-size bound for arbitrary preview payloads.
