---
title: "First chat presentation implementation slice"
created: 2026-09-07
updated: 2026-09-08
tags: [marmot, architecture, projections, implementation-plan]
---

# First chat presentation implementation slice

Implementation plan for [#1517](https://github.com/marmot-protocol/mdk/issues/1517), under
[#1742](https://github.com/marmot-protocol/mdk/issues/1742). This is the first C2/C3 slice; the C1 design needed for this
slice is ready. P1 supplies selection/storage; P2 adds background maintenance and recovery. Native APIs and
client adoption remain P3–P4. No client performance success is claimed. Later screen contracts retain their own design
and acceptance work. The [broader contract draft](chat-screen-contract-draft.md) maps those boundaries.

## Outcome and scope

A native client obtains each conversation's selected title and avatar descriptor in its chat-list result, including
on offline reopen. MDK owns the group/peer choice, cached identity, invalidation and background refresh. The client
can remove title/avatar roster/profile lookups while keeping unrelated roster consumers.

This slice preserves the existing list query cardinality and archive-inclusion behavior. It is deliberately an
incremental replacement for current list presentation, not the final bounded/paged screen API. C4 adds bounded windows,
composable filters and account-attention changes using the same row presentation type. Existing message previews,
unread counts, drafts, delivery, pin and lifecycle behavior remain under their current owners in this slice.
Avatar **descriptors** are durable here; offline avatar bytes belong to C7/#1554. No retained-media implementation,
accepted-edit resolver, new protocol component or separate low-level binding package is required to ship this slice.

## Concrete public contract

The following names define the planned API, subject to repository naming conventions at implementation. Their semantics
and ownership are fixed for this slice. Rust owns the policy; UniFFI and C perform mechanical conversion.

```text
PresentedChatRow {
    row: ChatListRow                  // complete existing row fields, unchanged semantics
    presentation: ConversationPresentation
}
ConversationPresentation {
    title: PresentationText
    avatar: SelectedAvatar
    title_source: GroupName | PeerProfile | PeerFallback | GroupFallback | UnknownFallback
    avatar_source: GroupImage | PeerProfile | GroupFallback | UnknownFallback
    peer_id: optional opaque identity // only if durable roster identifies self + exactly one peer
    resolution: Cached | LastKnown | Fallback
}
PresentationText = Literal(text) | LocalizedFallback(kind, member_count?)
SelectedAvatar = RemoteImage(url, cache_key)
               | EncryptedGroupImage(existing_group_image_material, cache_key)
               | Placeholder(stable_seed, Group | Person | Unknown)
PresentedChatListSnapshot {
    rows: sequence<PresentedChatRow>
    presentation_version: { account_store_epoch, revision }
}
OpenedPresentedChatList {
    snapshot: PresentedChatListSnapshot
    subscription: PresentedChatListSubscription
}
PresentedChatListUpdate {
    subscription_generation, sequence
    snapshot: PresentedChatListSnapshot
}
```

- `open_presented_chat_list(account, include_archived)` returns the snapshot and an already-attached subscription.
  `presented_chat_list(account, include_archived)` and `presented_chat_list_row(account, group)` provide local one-shot
  reads for existing narrow/use-at-creation flows. Normal ready reads perform no network fetch or repair writes.
- Initially emit complete replacement snapshots using the existing list reconciliation approach. They are easy to
  adopt correctly at current list sizes; C4 can introduce bounded window updates without changing row selection policy.
- `presentation_version` covers durable selected presentation only. Do not interpret it as a revision of the entire
  engine, directory or existing row fields. Subscription generation/sequence orders **all** emitted snapshots; equal
  presentation revisions must never discard a later read-state, delivery, pin, mute or lifecycle update.
- `Cached` means valid local evidence, not network freshness. `LastKnown` means valid same-subject display retained
  while a known newer profile is pending. `Fallback` means the selection lacks usable identity/profile evidence.
  An accepted profile that removes a name/avatar clears that value and recomputes fallback; a failed refresh alone
  does not erase valid cached data.
  Peer replacement clears invalid old-subject values; no public `Invalidated` state may carry the old person's display
  as the current peer. Never downgrade a valid cache merely because the process restarted or network is offline.
- Peer fallbacks reuse MDK's deterministic pseudonym helper with a canonical normalized identity. Group fallback uses
  `LocalizedFallback(UnnamedGroup, member_count)`; unavailable/unknown roster uses `UnavailableConversation`.
  A self-only unnamed group uses the group fallback, not an invented peer or new notes-to-self feature.
- Titles and profile URLs pass through shared bounded validation/sanitization. Empty/invalid display-name candidates
  fall through to usable profile name, then deterministic fallback. Client localization renders the typed fallback;
  it never decides whether this is a DM/group to choose a title.
- Avatar selection is independent of title selection. `SelectedAvatar` tells the image loader what source to use;
  no client peer/group inference is needed. Reuse existing validated group image material and loaders in this slice.
  Descriptor shape must accommodate C7's additive local-access API without embedding image bytes into list rows.
- The C API gains new whole-result types/functions and matching deep-free/subscription lifetime functions. Keep
  existing exported struct layouts/functions unchanged. Do not add a peer-only sidecar call. Rust/Swift/Kotlin also
  retain existing entry points during migration. New record/enum debug output must follow existing privacy rules.

### Selection matrix

| Local evidence | Title | Avatar without an explicit group image |
| --- | --- | --- |
| Nonempty explicit group name, any size | Group name | Peer avatar only if roster proves self + one peer; otherwise group placeholder |
| Empty name, exactly self + one peer | Usable peer profile name, otherwise deterministic peer pseudonym | Usable peer image, otherwise person placeholder |
| Empty name, known roster other than self + one peer | Localizable group fallback with member count | Group placeholder |
| Empty name, unknown/quarantined roster | Localizable unavailable-conversation fallback | Unknown placeholder |
| Same peer, newer profile awaiting apply | Last usable same-peer selection | Last usable same-peer selection |
| Peer replaced or roster no longer qualifies | Recompute against new evidence; never carry old peer as current | Recompute or placeholder; never reuse old peer cache key |

An explicit group image wins in every row independently. When both group sources are present, valid encrypted
group image material takes precedence over the group avatar URL; the URL is the fallback when encrypted material is
absent or invalid. Terminal lifecycle flags and command restrictions remain
unchanged; a screen record does not authorize a mutation. Current projected membership determines peer eligibility.

### Names and historical data

Verified current iOS/Android direct creation passes an empty name. Keep generated display derived, never written back
into the group profile. Treat nonempty shared names as explicit unless reliable producer/history evidence establishes
a generated default. Preserve ambiguous historical names, including a deliberately chosen name equal to a fallback.
Do not guess from text or rewrite signed group data during a local projection migration. Add support for a proven
historical generated-name format only with a fixture and participant-consistent provenance; no such format is required
by the verified current creation paths.

## Persistence and maintenance design

### Account projection

Extend existing account storage, not a parallel chat database:

- A versioned selected-presentation value on `chat_list_rows`, including dependency identity and applied profile version.
- A dependency index from identity to affected group/role. Named two-person groups may still depend on a peer avatar;
  the existing unnamed-direct lookup index alone is insufficient. Group/profile changes maintain this index atomically.
- Projection metadata containing a random store epoch, monotonic presentation revision, format/backfill progress and
  directory catch-up checkpoint. Reset/replacement changes the epoch; ordinary restart does not. Never use wall-clock
  time or remote profile timestamps as the local revision.

No new full-profile account table is needed for this slice. Read selected accepted directory evidence in bounded local
batches before the account write, then persist the selected row values. Readiness and dependency changes must be
revalidated under the account transaction; never combine a newly selected peer ID with previously cached peer data.

Account-local group/roster mutations commit either the new valid presentation or durable dirty state with a
same-subject last-known value or safe fallback. Name/image changes and row creation use the same resolver. Existing source/timeline/
chat-row transactions introduced by #1737 must be retained. Coalesce work per affected group; repair must not scan
message history, rebuild every account group, or introduce a second send/operation queue.

Advance the presentation revision only when selected presentation/validity/dependencies change, in the same account
transaction as those changes. Profile-only writes must not change activity clocks, unread/read intent, pins or archive.
Account deletion removes projection, dependencies and checkpoint through the existing account-store lifecycle.

### Durable cross-store profile propagation

Use a coalesced latest-change index, not an unbounded event replay log:

1. In the shared directory transaction, persist the accepted profile and a local presentation revision for that
   identity. Keep one latest revision/change row per identity, with a shared-store epoch and monotonic counter.
   Only actual profile/presentation changes advance it; duplicate relay/cache observations do not.
2. Put this bookkeeping at the shared storage write boundary so normal saves and legacy directory import both
   participate. Preserve existing directory winner/equal-timestamp rules. The revision records an accepted local
   change; it never makes an older remote profile authoritative.
3. Each account tracks the processed shared-store epoch/revision and any current identity/group batch progress.
   Query changes in revision order up to a captured high-water mark in a short shared-store read transaction.
   Capture the revision and corresponding accepted profile together. Release that transaction before taking the
   account write lock; do not nest shared/account locks or claim distributed atomicity.
4. Resolve current account dependencies, refresh at most 50 affected rows per account transaction, and commit selected
   values, revision and resume progress together. Process at most 50 changed identities per scheduling batch, yielding
   between batches. An account watermark advances only after the covered identities' dependencies have been handled.
5. If a profile changes again during processing, newer work supersedes old work and restarts that identity's dependency
   pass as needed. A coalesced row moving above a captured high-water mark is handled by the next pass; it is not lost.
   Compare applied source revisions so a delayed older batch cannot overwrite a newer application.
6. Creating a new dependency hydrates its latest local profile regardless of the catch-up watermark. This covers
   profiles cached before chat creation and groups created while another identity batch is in progress.
7. Shared-store replacement/epoch mismatch triggers bounded reconciliation of account dependencies. Profile removal
   or invalidation must record a change/tombstone while dependent accounts need it; never silently drop evidence that
   stale display must be cleared. Delete/coalesce tombstones only after proving no dependent account needs them or
   forcing epoch-based reconciliation. The change index holds no private account/group lists or media secrets.

The runtime resumes pending work while running, including with no screen subscribers. A suspended/stopped or inaccessible
account store retains its checkpoint and catches up on reopen. Idle processing does no full directory/group scan.
Use the existing maintenance scheduling/lifecycle rather than create another runtime framework. Poll a small shared
revision/checkpoint through that scheduler as recovery for a missed wakeup; events keep the normal path prompt.

### Snapshot and notification handoff

- Attach the runtime event receiver before reading the initial local snapshot. Return the snapshot and subscription
  together. Every emitted update is a newly read complete result, not a stale raw-event payload patched by the client.
- Publish a presentation invalidation only after the account commit. Runtime maintenance compares the committed
  presentation revision with its last-notified revision, so commit-before-broadcast interruption recovers even if no
  later message arrives. Runtime restart also forces an initial comparison. Share this mechanism per account, not
  one timer per subscriber; normal events should not wait for the fallback maintenance tick.
- Read existing row fields and persisted selected presentation from one account read transaction where possible;
  revalidate the presentation revision for any enrichment that must occur outside it. Retry/reconcile inside MDK
  rather than returning a new peer identity with an old presentation. Same-subject last-known display is permitted.
- Each subscription owns a fresh generation and monotonic sequence; only its current generation may update the UI.
  On lag/overflow, rebuild from current local state and emit a replacement. Cancellation, account switch and shutdown
  terminate the handle using existing lifecycle conventions. No durable public change stream is promised.
- Preserve existing event routes for non-presentation row fields, including mute-expiry refresh. The new presentation
  token supplements those routes; it does not redefine their authority or silently claim cross-field atomicity.

## Upgrade and rollout

Use new numbered account/shared migrations after the current highest migrations; do not reserve a number now or
change workspace versions as feature work. Schema migrations add representations and markers transactionally; seed
existing directory rows with revision zero. First account preparation hydrates its dependencies directly, so it does
not need an all-directory rewrite to manufacture historical revisions.

Backfill selected rows in bounded batches of 50 with durable progress and a format version. Existing legacy APIs remain usable.
The new open operation can await local preparation asynchronously; never block the host UI thread or wait on network.
An upgrade that cannot complete reports typed preparation/storage failure, not a false cache miss. Do not advertise
that the first upgrade has the same latency as a ready reopen. Measure it separately. For this first, existing-cardinality
list API, completion may cover the account's list; C4 owns bounded first-page readiness for the final screen contract.

Interrupted migrations roll back; interrupted backfill resumes idempotently. Keep group names, user preferences,
read anchors, draft content, history and media secrets intact. Old rows/profile sources remain available until new
projection readiness is durable. Rollback means old **APIs on the upgraded runtime** remain usable; older released
binaries opening a newer schema are subject to existing compatibility policy, not a promised binary downgrade.

## Merge and adoption sequence

| Unit | Repository / deliverable | Depends on | Independently reviewable result |
| --- | --- | --- | --- |
| P1 | MDK: pure selection policy, selected-row storage/dependency index, account migration and resumable backfill | This plan | Tested internal durable representation; existing client behavior remains usable |
| P2 | MDK: shared profile revision index, account catch-up, all source mutation hooks and crash recovery | P1 | Presentation stays correct without subscribers; targeted work and recovery tests pass |
| P3 | MDK: additive Rust/UniFFI/C presented-row reads and snapshot subscription | P1 + P2 | Complete supported native capability; binding parity, ownership and upgrade/reopen checks pass |
| P4a | Android: adopt selected title/avatar in chat rows and creation/rebind paths | Released P3 artifact | Removes display-only roster/profile fallback work; verify Android #2149 and before/after fixture |
| P4b | iOS: adopt the same contract in list and creation/rebind paths | Released P3 artifact | Removes display-only selection/enrichment; verify offline first frame and profile updates |

P1/P2 may merge as internal foundations; they are not separate user-facing launches. Ship the public capability only
when P3's contract is complete. P4a/P4b can release independently. Keep commits/PRs focused on these boundaries; split
an unusually large migration/test patch further without publishing an incomplete API. C1 does not require a new
configuration/feature-flag framework. Later C4-C8 work can reuse the published presentation value and resolver.

### P1 implementation boundary

The account migration adds versioned selected values, dependency/roster indexes, and random account/row incarnation
identifiers. Compare-and-store rejects preparation from a replaced store, recreated row or older source generation.
The partial index of absent or unapplied source revisions is the durable backfill worklist: committed rows leave it, dirty rows rejoin
it, and each read returns at most 50. This avoids skipping newly inserted or invalidated rows behind a global cursor.
Ordinary reads distinguish missing, pending and ready without repair writes. Profile bookkeeping alone does not advance
the selected-presentation notification revision. Same-subject name/image changes keep the committed value and
dependencies renderable as `LastKnown` until refresh; membership changes clear invalid old-subject display immediately.
Explicit name/image removal also clears the selected value immediately, including the canonical absent avatar
component and component deletion. Replacement keeps last-known display; removal must not expose the removed source.
The read-time freshness annotation does not itself advance the committed-value revision, and identical recomputation
does not notify. Corrupt/unsupported envelopes return redacted read errors but a current-generation write can replace
them. Future format changes must advance the account schema and migrate or invalidate old envelopes; the schema
compatibility gate prevents an older binary from opening those newer-format rows. Decode failure alone does not queue work.
`ChatPresentationWrite::Applied` reports committed row/dependency/progress work, including an identical refresh;
notifications use the committed presentation revision rather than this write result.

P1 seeds only roster evidence already available in the direct-member index. P2 carries authoritative two-person
rosters for named groups through source projection transactions and live reconciliation before draining backfill.
Missing roster evidence yields a typed fallback; later hydration uses the roster setter to requeue it, without
creating a permanent busy retry loop for legitimately unavailable/quarantined groups.
The P1 methods and resolver are internal Rust building blocks; existing app, UniFFI and C chat-list behavior is unchanged.
P2 authorizes shared-store epoch transitions at its checkpoint boundary; delayed work from an older checkpoint
or directory incarnation cannot overwrite a newer application. P3 supplies atomic whole-row reads and subscription handoff.

### P2 maintenance boundary

Shared schema 3 records one latest change per identity, comparing accepted `display_name`, `name`, and `picture`.
Timestamps, relay observations and unrelated metadata do not advance this revision. Triggers cover normal saves,
legacy import, and profile removal; tombstones remain until a future cleanup can prove no account needs them.

Account schema 66 persists the directory incarnation, processed revision, active identity/group cursor and reset
reconciliation cursor. Selected rows and checkpoint progress commit together. A newer coalesced change abandons the
old identity cursor without skipping intervening identities. New dependencies always hydrate from the current shared
cache, even behind the watermark. Store replacement captures the shared head and reconciles at most 50 rows per step,
then processes changes since that head. Unrelated changes advance in batches of at most 50 identities. Idle steps use only indexed
pending-work and revision reads; they do not scan groups, directory history, or messages.

The existing account worker runs these bounded steps after readiness, yields between batches, and stops with its
normal lifecycle. Coalesced process-local wakeups cover directory/source writes; the existing 15-second maintenance
tick recovers missed wakeups. A batch with no checkpoint or row progress stops immediate rescheduling and retries on a later wakeup/tick. A fresh worker compares committed presentation revisions before notifying, recovering
commit-before-broadcast interruption. These internal invalidations are the P3 subscription input.

Groups missing a legacy chat row use a durable, bounded initialization queue and the existing row projector. This
initialization retains the legacy projector's query cost; refresh and queue completion commit atomically even if a
chat row already exists. Only durable completion counts as initialization progress. Profile refresh and steady-state
repair do not
rebuild history. Quarantined rosters lose current peer evidence until live reconciliation supplies it again; existing member counts and direct-conversation reuse indexes remain intact. Two-person roster identities use the same canonical order in memory and storage.

### Consumer accounting

- Android `ChatsController` member/presentation caches also support folders, shared groups and profile actions. Remove
  their dependency for row title/avatar rendering; preserve other callers. Do not delete the entire cache in P4a.
- iOS `ChatsListViewModel` uses membership-page reads/fallbacks for enrichment; `DirectChatStarter` seeds a created row.
  Adopt the new whole-row result at both paths, preserving non-display member operations.
- Conversation view models currently combine group/timeline subscriptions and snapshots. Their replacement is C5,
  not an extra requirement on P4 list adoption. Lower-level CLI/agent/raw-event queries stay supported.
- C mirrors remain additive and deeply freed; test embedded legacy fields plus new descriptors exactly once. Swift/
  Kotlin wrappers and generated artifacts must come from the same Rust contract. No host stores a second durable
  selected-presentation cache to make the new API work.

## Acceptance matrix

| Scenario | Required proof |
| --- | --- |
| Profile cached before chat creation; restart/offline | First presented result has the selected peer data without network or per-row client profile/roster lookup |
| Named/unnamed two-person, larger, self-only and unknown roster | Selection matrix passes; title/avatar precedence independent; typed fallbacks deterministic |
| Empty display name, invalid profile/avatar, custom name equal to generated display | Safe candidate fallback; no guessing or overwriting explicit group names |
| Peer A replaced by B; two-person becomes larger or roster invalidated | Same transaction removes A as current peer; safe B/group fallback while hydration proceeds |
| New/duplicate/stale profile, profile-only change | Correct winner; no duplicate generation/write amplification; stable activity/read/archive state |
| Shared commit before wakeup; account row commit before broadcast; restart mid-batch | Replay/resume converges with no active screen and without another incoming message |
| Account created or new dependency added after watermark; coalesced newer profile during pass | No missed hydration, no old-batch rollback, no skipped affected group |
| Account/shared store reset; profile invalidation; account deletion | Epoch/reset and removal recovery; isolation; no stale peer revival |
| Subscribe/read race, lag, repeated snapshot, equal presentation version with changed unread state | Complete newest snapshot, monotonic per-handle sequence; no lost non-presentation update |
| Populated migration/backfill failure, cancellation and reopen | Existing intent/data preserved; typed readiness; no partial-cache success or UI-thread blocking |
| Swift/Kotlin/C API and creation paths | One whole result supports selected display; enum cases covered; C layout and deep-free safety |
| Increasing unrelated history/groups/directory entries | Indexed affected-row work; ready reads have no history scans, network work or projection writes |

Use meaningful existing regression foundations and add targeted storage, app-runtime and binding tests for new seams.
Run `just fast-ci` before pushing, touched-crate tests, and C parity/header/smoke/alloc-audit gates when P3 changes them.
Native adoption follows each client's own screenshot/device-test requirements. P1/P2 tests cover storage and local maintenance; native binding and client validation remain P3/P4 work.

For performance, preserve the recorded Pixel 9a / 20×40 fixture and artifact provenance. Measure native presented-list
read, profile commit-to-update, first upgrade and ready offline reopen separately from whole-app startup. Report p50/p95
and workload/query work; use the existing whole-client runs for comparable before/after evidence. Provisional parent
latency targets are not automatic release gates. Do not expand this slice into unrelated startup or packaging repairs.

## Evidence and remaining scope

MDK baseline: `788eaf0852442cb31311fd72d9dd6ea91c2642a6`; reviewed as a focused diff from the local
`91221c86585387d0d029466728c86e765ed14150` inventory. Refresh touched source and migrations when implementation starts.
Relevant owners: `storage-sqlite/src/chat_list.rs`, `account_projection.rs`, `shared.rs`; `marmot-app/src/directory/methods.rs`,
`groups.rs`, `client/projection.rs`, `lib.rs`, `runtime/subscriptions.rs`; UniFFI chat-list conversions and commands;
C types/commands/subscriptions. Shared directory writes occur in normal saves **and** legacy import.

Native evidence: iOS `190ac82c7f069cf49e05bb27a6552547a20c9ead`, Android `3af7335263c9134503f04b061578a80a9b0ee346`.
This is sufficient consumer accounting for list presentation; it is not a complete inventory for later conversation,
media, or non-chat binding removal. Those children must finish their own detailed contracts before implementation.
