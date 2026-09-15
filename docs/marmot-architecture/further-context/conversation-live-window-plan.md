---
title: "C5 M4 live conversation implementation plan"
created: 2026-09-15
updated: 2026-09-15
status: implementation-plan
---

# C5 M4: one live conversation handle

M1–M3 are merged through #1844 (`1fcb060b6`). M4 in #1838 composes their Rust foundations;
M5 exports native handles. The independent account badge correction #1847 is merged.
The viewport and account-read foundations merged in #1849; M4 is not yet complete.

## Contract to implement

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
2. **Coherent capture — account boundary merged; compact engine foundation implemented.**
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
3. **Actor and handles.** Attach projection/group, draft, relevant profile, presentation and reset
   sources; serialize page/anchor/latest requests; deliver complete replacements with retries.
4. **Adversarial integration coverage.** Race initial read vs mutations, concurrent receive/page,
   draft acceptance vs newer edits, permission changes, quiet contention recovery, lag, retention,
   store eviction and teardown. Record row/source-work bounds separately from payload byte size.

These are implementation checkpoints within #1838, not promises of independently shippable screen
APIs. Foundation PRs can merge on their own tested contracts; M4 is complete only when the combined
live handle and adversarial integration coverage pass.

## Source audit and the capture gap

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

The next actor PR must wire the session capture callback during ordinary operation and explicitly
retain a retry obligation while startup or recovery owns the mutable client; it must not substitute
`GroupReadSnapshot` while catch-up runs. Pin the worker response and retry behavior in those paths.
Prototype against both live and startup-snapshot paths.
Cached facts must be invalidated by role/membership/capability/lifecycle
changes, must not survive a store replacement, and cannot be combined with a different account
frontier. Do not use a generic `Stable` fallback for unknown epoch state or silently omit a
permission because it is expensive to compute. Command validation remains authoritative.

No new product decision is required. This is an engineering capture dependency, not a reason
to change opening, invitation, archive, scroll or read-acknowledgement policy.
