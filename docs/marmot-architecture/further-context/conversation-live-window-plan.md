---
title: "C5 M4 live conversation implementation plan"
created: 2026-09-15
updated: 2026-09-15
status: implementation-contract
---

# C5 M4: one live conversation handle

M1–M3 are merged through #1844 (`1fcb060b6`). M4 in #1838 composes their Rust foundations;
M5 exports native handles. The independent account badge correction #1847 is merged.
The viewport/account-read foundations merged in #1849 and compact authority in #1852.
The Rust actor below completes their live composition; native handles remain M5.

## Implemented Rust contract

- One account/group and one actor per handle. Open at first unread, otherwise latest.
  Initial snapshot and later replacements contain history, read position, descriptor-only draft,
  selected header/capabilities and every identity referenced by returned content.
- Attach all change/reset/shutdown sources before the first read. Commands and invalidations use
  the same actor; `recv` must not hold a command lock. Commands carry generation/sequence and
  stale requests fail explicitly. Accepted commands outlive caller cancellation.
- Reuse the existing materialized timeline, canonical anchors and 200-row cap. Older/newer paging
  adjusts context around the visible anchor; clients retain pixel offsets. Explicitly report
  retained/recovered/empty anchors and expose a return-to-latest command. Do not recenter on
  unread when ordinary updates arrive or infer that paging acknowledges reads.
- Read account-owned fields under one account snapshot. Hydrate directory identities afterward
  and reconcile queued invalidations. Directory data is a separate consistency domain.
- Failed refreshes are explicit and retain a timed retry obligation without requiring traffic.
  Reset, account-store replacement, shutdown and subscription drop close the handle. A surviving
  command clone must never keep an abandoned window alive or rebind to another store.

## Implementation checkpoints within M4

1. **Viewport placement primitive — implemented.** `conversation_window` adds explicit context before
   a retained anchor over M1's read/recovery implementation. Test extension in both directions,
   edge filling, anchor removal and unchanged read intent; retain M1's bounded-query tests.
2. **Coherent capture — implemented.**
   `conversation_account_snapshot` captures timeline/provenance, selected presentation inputs,
   read state, revisioned draft descriptors and persisted archive/admin/leave controls in one
   deferred read. A concurrent WAL writer test verifies that every field stays on the same
   snapshot. `Engine::group_authority` now returns compact role, membership and capability facts;
   lifecycle and pending disband gates remain fresh. It reuses the existing MLS cache and derives
   compact scalars on each capture. No new durable revision/cache table is introduced; measure
   actual actor refresh costs before adding finer-grained invalidation. Membership includes the
   existing staged record projection, while admin authority changes at canonical acceptance.
   `AccountDeviceSession::with_group_authority_snapshot` composes host-owned account reads on the
   session's exact connection, under one enforced read-only transaction and live engine borrow. Startup
   seeds fail with `GroupNotHydrated` until validated; missing live epoch state returns `UnknownGroup`.
3. **Actor and handles — implemented.** Attach projection/group, draft, relevant profile, presentation and reset
   sources; serialize page/anchor/latest requests; deliver complete replacements with retries.
4. **Adversarial integration coverage — implemented.** Race initial read vs mutations, concurrent receive/page,
   draft acceptance vs newer edits, permission changes, quiet contention recovery, lag, retention,
   store eviction and teardown. Record row/source-work bounds separately from payload byte size.

These are implementation checkpoints within #1838, not promises of independently shippable screen
APIs. Foundation PRs can merge on their own tested contracts; M4 is complete only when the combined
live handle and adversarial integration coverage pass.

## Source audit and resolved capture gap

| Source on merged M3 | Reuse / remaining work |
| --- | --- |
| `storage-sqlite/src/timeline/opening.rs` | Canonical recovery and prepared read state, one deferred read. Explicit viewport placement is the first M4 addition. |
| `storage-sqlite/src/message_drafts/revisioned.rs` | Keyed descriptor-only draft and revision token. Never call the attachment-hydrating draft getter from a screen read. |
| `marmot-app/src/conversation_presentation/window.rs` | Header/identity builder and immutable provenance page. M4 must supply a coherent `ConversationHeaderState`; this API does not capture it. |
| `marmot-app/src/runtime/subscriptions.rs` | Existing bounded timeline machinery and routing. Its independently updated page cannot simply be zipped with separately read header/draft state. |
| `marmot-app/src/runtime/chat_list_window.rs` | Existing actor, cancellation, source attachment, retry and store-reset patterns. Reuse the behavior without coupling conversation handles to chat-list policy. |
| `marmot-app/src/client/mod.rs::group_mls_state_unchecked` | Reads a group record including its members; lifecycle also comes from the in-memory epoch manager. When lifecycle support is not enabled it calls the engine's MLS-backed blocker query. Not yet a compact screen-capture path. |
| `cgka-engine/src/disband.rs::disbanding_support_blockers` | Loads OpenMLS state and examines leaf support. Calling this per message/profile/draft refresh would reintroduce roster work. Do not guess an empty blocker set or fabricate enabled actions. |
| #1793 | Still open and separately owned. Removes the whole-account lookup for one group; does not alone solve compact engine authority or cross-source coherence. |

The existing `presentation_source_revision` cannot serve as an authority revision: migration 0065
invalidates it for title/avatar/member presentation changes, not admin policy or engine lifecycle.
The startup/recovery `GroupReadSnapshot` freezes engine facts before network work while account
storage can advance. Zipping its MLS state with a fresh account capture is therefore not coherent.

The actor uses the session capture callback during ordinary operation and retains a timed retry
while startup or recovery owns the mutable client. All three frozen-snapshot dispatch paths return
`NotReady`; they never combine `GroupReadSnapshot` with newer persisted fields. Startup hydration
and ordinary command dispatch use the live capture. Tests cover unavailable frozen snapshots,
quiet retries and an ordinary managed worker.
Cached facts must be invalidated by role/membership/capability/lifecycle
changes, must not survive a store replacement, and cannot be combined with a different account
frontier. Do not use a generic `Stable` fallback for unknown epoch state or silently omit a
permission because it is expensive to compute. Command validation remains authoritative.

No new product decision is required. This is an engineering capture dependency, not a reason
to change opening, invitation, archive, scroll or read-acknowledgement policy.

## Handle and recovery behavior

`MarmotAppRuntime::open_conversation_window(account, group, ConversationOpenQuery)` returns the
initial `ConversationWindowSnapshot` and `RuntimeConversationWindowSubscription`. The snapshot
contains the provenance-bearing timeline page, header/identity sidecar, raw retained read state,
selected revisioned draft and one canonical anchor token per row. Pending invitations retain raw
read counters; effective participation and actions come from the header capabilities.

`window_handle()` provides independent `page(Older | Newer)`, `set_visible_anchor`,
`jump_to_message` and `return_to_latest` commands. Each carries the current generation/sequence;
a generation belongs to one open handle. Invalid/stale requests fail explicitly. Latest mode
follows new arrivals. First-unread opening, an explicit visible anchor or paging into history
retains that message and context; ordinary updates never recalculate first unread. The client
explicitly returns to latest to resume following the tail. Paging retains
at most 200 rows: to continue beyond that context, the client reports its new visible anchor.
Pixel offsets and read acknowledgements remain separate client actions.

All source receivers attach before opening. Directory enrichment happens after the account
capture; events arriving during either step remain queued for another read. Slow consumers get
the latest complete replacement. Unchanged content does not generate redraws. A failed refresh
retains a one-second retry obligation even without traffic. An accepted command outlives caller
cancellation; transient failure retains its requested position. If a deferred explicit target
expires before retry, the stream reports that error and resumes the last successful viewport.

Opening performs no network request of its own. It can remain pending while an existing startup
or recovery operation exclusively borrows the account client; retrying avoids publishing stale
permissions. Cancel the opening future to abandon that wait. Later capture failures are stream
errors followed by timed recovery. Shutdown, store eviction/replacement, a lost reset signal,
or dropping the subscription terminates the actor even if a command clone survives. The worker
sender is pinned and is never reacquired for an existing window.

## Validation and work bounds

Actor tests exercise first-unread opening, concurrent receive/page, both revision components,
row caps, cancellation, initial-capture/draft races, late draft clearing, profile-only updates,
invitation acceptance/archive/departure capabilities, expired anchors, lag, quiet worker/storage
retry, target expiry during retry, eviction, closed storage and shutdown. A worker dispatch test
pins `NotReady` with and without a frozen snapshot; an integration test opens through the ordinary
managed worker. M1/M2/M3 and account/authority capture tests remain the underlying semantic evidence.

One actor retains the initial snapshot, current snapshot and latest coalesced replacement, each
with at most 200 timeline rows and M3's bounded identity sidecar. The command queue holds eight
requests; drains consume at most 1024 queued signals per source before a capture. Selected draft
reads never load attachment blobs. The ordinary capture uses one group, one account read boundary
and existing MLS state; dirty read projections may require their existing owner's keyed repair
before retry. This is not a constant-time guarantee for legacy unread reconstruction or engine
membership inspection. Row/reference bounds are distinct from transcript/draft text byte size;
this work introduces no new absolute byte cap and makes no device-speed claim. See
[the runtime state inventory](../runtime-state-bounds.md).

M5 adds UniFFI/C DTOs and ownership/error mapping over this Rust contract, with generated native
parity tests and client migration examples. Bindings publication, app adoption and device timings
remain C9.
