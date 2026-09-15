---
title: "Native chat-list and account-attention handoff"
created: 2026-09-14
updated: 2026-09-15
status: implementation
---

# Native chat-list and account-attention handoff

C4 M4 ([#1777](https://github.com/marmot-protocol/mdk/issues/1777)) exposes M2's
bounded list windows and M3's independent attention through additive UniFFI and C
APIs. Swift and Kotlin are generated from the same Rust declarations. This adds
no schema, second projection store, or release version bump.

## Host flow

1. Open `openChatListWindow(accountRef, view, initialRows)` for one account and one
   of Chats, Unread, Archived or Left. Omit the size for 50 rows; explicit requests
   must be 1–100. The runtime retains at most 200 rows.
2. Take `snapshot()` once, before starting the receive loop. `nil`/`null` on a
   second call means the initial snapshot was already taken, not an empty list.
3. Await `next()` on one task and replace the installed window wholesale. Render
   every row's `presentation` for title/avatar. Localize fallback tokens on the
   client. Use the row's effective badge fields without recomputing eligibility.
4. Send `page(sequence, direction, count)`, `setVisibleAnchor(sequence, groupIdHex)`
   or `returnToTop(sequence)` on another task. Commands do not wait for the
   receiver lock. Use the installed sequence. Their responses are complete
   replacements and are also delivered through `next()`; discard duplicates and
   older sequences within the same generation. Accept a new generation only from
   the currently selected newly opened handle, never an obsolete account/view task.
5. Preserve the visible row's pixel offset locally. `anchor` reports Top,
   Retained, Recovered or Reset; Retained/Recovered include stable identity and
   index in the replacement. Report the new viewport anchor before continuing
   paging when the 200-row cap would otherwise evict the protected row.
6. Open `subscribeAccountAttention()` separately for the account switcher and
   badges. Take its initial snapshot, then replace the complete account set on
   updates. `Ready` carries counters; `Unavailable` carries only Preparing,
   ReadFailed or Resetting. `unreadConversations > 0` means attention. The application
   badge is `unreadCount + attentionOnlyConversations`: each unarchived pending invite
   adds one attention-only item, as does an accepted manual reminder without unread
   messages. Invites never add message/mention counts before acceptance; archived and
   departed/departing chats add nothing. Missing accounts have left the signed-in
   set. Do not substitute zero for unavailable entries or derive totals from loaded
   list rows. Counters are coherent per account, not across all databases at once.

The native snapshot deliberately does not serialize the Rust storage `first` and
`last` cursors. They are internal boundaries owned by the window actor; no native
command consumes them. `hasMoreBefore/After`, rows and generation/sequence are the
complete native navigation contract. Do not persist sequences as restart tokens.

## Errors, cancellation and ownership

`ChatWindowStale` means use the latest delivered sequence; never append the stale
page. `ChatWindowInvalidLimit` and `ChatWindowAnchorOutside` reject bad commands.
`ChatWindowClosed` requires reopening. `ChatWindowQuery` reports a terminal internal
navigation failure. App failures retain the existing typed errors, including
StorageBusy, StorageClosed and RuntimeStopping. Runtime read failures retain the
refresh/retry behavior documented by M2/M3; an account-catalog error is a stream
error, not an empty account set.

Cancellation of `next()` does not consume an update. A queued command may complete
when its caller is cancelled; observe the replacement stream before retrying.
Only one receive loop should consume a handle. On account/view switch, cancel the
old loop and release the handle. Swift releases ARC references after cancelling
its tasks; Kotlin closes/destroys its UniFFI object after cancelling and joining
its consumer job. An outstanding method call retains its object. Runtime shutdown
ends both streams; account resets also close affected list windows. Use
`shutdownAndClose()` for terminal suspension/root-lock release.

C uses `marmot_open_chat_list_window` and `marmot_subscribe_account_attention`.
The initial-size pointer is borrowed and optional (NULL selects 50); view/direction
are validated `uint32_t` discriminants. Every fallible call preflights and clears
its output pointer before opening a handle, consuming a snapshot, or issuing a
command. `_next` uses zero timeout for indefinite waiting, TIMEOUT for no update,
and CLOSED for stream end. Error/timeout/closed results leave output NULL. These
fallible streams expose blocking reads rather than an error-dropping callback.
Call from a host background thread; paging can run concurrently on another thread.

Each returned snapshot owns its nested rows, strings and tagged-union payloads.
Free with `marmot_chat_list_window_snapshot_free` or
`marmot_account_attention_snapshot_free`, including command responses. Freeing a
handle does not invalidate snapshots already returned. Free handles before their
client; never free while a call still uses the handle. Frees are NULL-tolerant.
Existing C layouts/status values remain intact; new window statuses append at 73–77.

## Adoption and acceptance

Keep existing full-list APIs for full-dataset search and custom folders. Filtering
only the loaded page cannot implement complete search. M4 does not remove legacy
list subscriptions, narrow reads, member caches or the old unread getter. Clients
can migrate the four default lists independently. Native adoption and viewport/UI
benchmarks remain C9; this code does not establish a device latency improvement.

M1/M2 bound SQL work, fallback identities and returned rows independently of retained
message history. Native conversion maps only the returned window, without another
read or retained conversion cache. The one-shot initial buffer moves its rows out
of the Rust subscription before conversion. Hosts control how many old snapshots
and handles they retain. The 200-row bound is not a byte cap on arbitrary previews.

Verification surfaces:

- UniFFI runtime test: concurrent next/page, stale/invalid commands, anchor/top,
  all four views, attention without an open list, cancellation and shutdown.
- C boundary tests: preflight before consumption/mutation, discriminant validation,
  timeouts, concurrent commands, terminal close, and allocation-audited deep frees.
- `chat-projections-smoke.sh swift|kotlin`: regenerate host bindings, compile the
  async command surface and execute window/anchor/availability/counter round trips.
- `just c-header`, `just c-parity-gate`, C smoke, touched-crate tests and `just fast-ci`.

Host smoke tests validate generated APIs and marshalling. They are not iOS device,
Android device, XCFramework/JNI release packaging, or application-adoption evidence.
