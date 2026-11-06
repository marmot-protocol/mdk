---
title: "Bounded live chat-list windows"
created: 2026-09-14
updated: 2026-11-06
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
Reopen returns a new generation.

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
requiring a new event. Internal query validation errors are terminal and retain
their error classification. Losing a teardown signal closes the window conservatively:
account cache eviction can preserve both account ID and durable store epoch, so a
refresh alone cannot establish that its lifetime survived. Timed mute expiry
refreshes the retained window when a visible row's mute expires, and when any
chat in the view's mute expires if the window's filter tests mute.

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
not show it); conversation kind (direct or group, as the row's
`conversation_kind` shows; a chat whose kind is still unknown matches neither);
muted, as the row's `muted` shows at the time of the read; chat text; and a
group ID list. Folder rules are ordinary filters: "excluded IDs always win" is
`All[Not(GroupIds(excluded)), Any[GroupIds(included), rule]]`, and an included ID
never adds a chat outside the base view. An empty `All` matches every chat in the
view and an empty `Any` none. Message text and people are later slices of #2983.

A query has at most 8 levels, 64 nodes, 500 group IDs and 1024 bytes of search
text in all. Over a bound, or
with a malformed node list, every consumer fails with `InvalidChatListQuery`
before reading; host group IDs are normalized like any other host group ID.

The filter compiles to SQL appended to the view's condition, ahead of keyset
paging, with every value bound as a parameter. Reads still walk the view's page
index in display order; each leaf is a `chat_list_rows` column or one keyed
lookup per chat (account groups, engine leave and disband records, the draft
tables and the mute settings). Cost grows with the chats in the view, never with
history.

Conversation kind is the `chat_list_rows.list_kind` column. Triggers keep it
current from the classifier's inputs, the row's group name and the account
group's member count, whichever writer changes them; the classifier still owns
the presented row's kind. Mute is not a column: a mute has an expiry, so the
`Muted` leaf tests the mute settings against the read's time, a bound parameter,
and nothing is written when a mute expires. Each read evaluates the leaf and every
row's `muted` at the same time, so they agree.

Chat text is the `chat_list_rows.search_text` column, written with each stored
presentation: the literal title, the group name, the description and, for a
direct chat with an eligible peer, the peer's profile display name and name.
Localized fallback titles (an unnamed group, an unavailable conversation) are the
host's text, so they are not searchable. Each field and the query are normalized
the way user directory search normalizes its query, by trimming and Unicode
lowercasing (`storage_sqlite::normalize_search_text`), and the query matches as a
literal substring of one field: `instr`, so `%` and `_` are ordinary characters,
and fields are joined by a control character no field or query can contain.
Text that is empty after trimming matches no chat. Accent and compatibility
folding are not applied; adding them is a deliberate format change.

The search text is only as current as the stored presentation. While any chat
in the query's view has its presentation pending (never prepared, or invalidated
by a name, description, avatar or membership change), a query with a text leaf
is not ready, never a partial set: `chat_list_ids` and `revalidate_chat_list_ids`
return `ChatPresentationNotReady`; opening a window waits, as it does for base
rows; and an open window publishes `ChatPresentationNotReady` and retries. Before
each such read the runtime runs a few bounded steps of the account's profile
catch-up and prepares one batch of the view's pending rows, so a text read does
not depend on a running account worker; catch-up still owed after those steps
is reported as not ready too. Queries without a text leaf never wait on
presentation outside their window.
Every eligible direct-chat peer is a presentation dependency, even under a group
name, so a peer's profile change re-prepares the chat's search text.

Every read is self-contained: each window read, `chat_list_ids` and
`revalidate_chat_list_ids` runs in one read transaction, so filtered and fixed
views behave alike. Storage keeps no cursor between reads. A window keeps its
place by re-reading around a stable anchor chat ID, and paging grows the window
instead of continuing a stored page.

Windows re-read on almost every account change already. Drafts are the exception:
a draft change wakes a window only when the chat is visible, unless the window's
filter tests drafts, in which case any draft change in the account re-reads it.
Mute expiry is not a change anything writes, so a window whose filter tests mute
also wakes at the next mute expiry among the chats in its view, visible or not:
a chat leaves or enters a muted window at its expiry. A text window also re-reads
on a profile change to anyone, and its read catches the search text up; every
stored presentation change, including one that alters only the search text,
advances the presentation revision every window re-reads on. So a profile or
description change makes an off-screen chat enter or leave a text window.

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
