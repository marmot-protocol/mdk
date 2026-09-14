---
title: "Chat screen contracts: C1 working draft"
created: 2026-09-07
updated: 2026-09-07
tags: [marmot, architecture, projections, chat]
---

# Chat screen contracts: C1 working draft

Status: C1's design gate for the first resolved-row implementation slice is complete in the
[first-slice plan](chat-presentation-first-slice.md). This broader document remains the ownership/reference map for
later screen work; their detailed paging, media and compatibility designs belong to their respective children.
No implementation or runtime validation is claimed by this design status.

Product decisions are recorded in the [inventory](chat-projection-inventory.md#9-product-decisions-from-the-contract-discussion).
The first-slice plan is authoritative for its concrete DTOs, selected fallback/name policy, commit/recovery design,
upgrade behavior, merge units and native adoption criteria. It supersedes the tentative first-slice wording below.

## Recommended ownership

Keep authoritative domain records and evolve the existing durable chat projection. A screen response composes prepared
local data in a bounded read; it is not another authoritative copy of messages, read intent or group membership.
Shared derivation belongs in `marmot-app` and storage helpers; UniFFI/C expose the same semantics.

| Output | Authoritative input | Recommended storage/read boundary | Update inputs / obligations |
| --- | --- | --- | --- |
| Conversation identity | Account-device and MLS group identity | Retain existing opaque IDs; do not substitute the Nostr route ID | Creation, account removal, group-local deletion |
| Title and avatar selection | Group profile/image, current membership, accepted directory presentation, name provenance | Persist the resolved row presentation and dependency identity/version; return one chosen title and avatar descriptor | Name/image/roster/profile changes; peer replacement; migration/repair |
| Preview content and kind | Canonical timeline, accepted edit/system semantics, selected draft | Maintain a small structured preview, including display dependencies; do not scan history on every list read | Messages, edits, deletion/expiry, invalidation/revalidation, draft save/clear |
| Preview sender and system subjects | Authenticated message/system identities plus cached presentation | Share identity resolution with the conversation surface; prepare required identities in the returned envelope | Relevant directory changes and content changes |
| Activity and order | Existing durable activity clock and pin order | Preserve existing activity ownership; maintain sort keys independently of preview text | New messages, accepted local sends, membership changes; pin changes affect pin order |
| Unread, first unread, mentions | Durable read anchor, canonical eligible messages and mention classifier | Reuse unread acceleration and transactional read-state/row updates | Message/read/retention changes and invitation acceptance |
| Manual unread | Durable explicit user intent | Keep independent flag; derive attention/filter membership without fabricated message counts | Explicit mark unread/read using current clearing rules |
| Archive and mute | Durable preferences and mute deadline | Reuse archive/pin/settings storage; compute effective mute from deadline even after downtime | Explicit changes, lifecycle transitions, clock expiry |
| Invitation and membership | Account confirmation state and authoritative group lifecycle | Expose independent typed state plus current permitted actions; revalidate at mutation time | Welcome, accept/decline, leave/remove/disband, recovery |
| Draft summary and composer | Existing encrypted draft and attachment records | Join bounded summary into list; include selected draft descriptors in conversation; bytes through separate local access | Draft version changes; durable send acceptance clears only the submitted version |
| Delivery and operation state | Durable send/receipt/operation owners | Reuse their typed states; never infer failure from time elapsed or equate relay ACK with peer receipt | Acceptance, publication, receipt, failure/retry and reconciliation |
| Account attention | Main-list eligible rows and independent manual-unread intent | Cheap per-account aggregate; no timeline/session load just to switch accounts | Same transactions/maintenance as contributing rows; exclude archived/pending invites |
| Conversation header/capabilities | Shared resolved row, current group/self membership and policy | Compose with existing group snapshot helpers; no full roster required for ordinary conversation open | Group/profile/lifecycle changes; policy changes; identity refresh |
| Timeline window and anchors | Existing canonical materialized timeline | Retain paged window manager; add complete presentation to each resulting window | Canonical timeline changes, paging, lag refresh and identity changes |
| Avatar availability | Validated cached bytes and current selected avatar descriptor | Durable bounded cache; descriptor/local-access state in envelope; no decoded bitmap persistence | Acquisition, source replacement, refresh, eviction, account cleanup |
| Attachment availability | Retained message references, media secrets, acquisition/removal records and validated bytes | Durable acquisition/retention outside timeline payloads; messages carry descriptors and availability | Receipt/acceptance, transfer completion/retry, storage pressure, explicit removal/reacquire, deletion/expiry |

Filters consume the same logical row projection. The complete list read must avoid external per-row calls and bounded
reads must not hide all-history or all-roster scans. Indexed joins and inexpensive derived flags are compatible with a
pre-baked screen contract; every field does not need its own duplicated column or table.

## Recommended initial-response shape

Use one open operation that returns an initial snapshot and its already-attached update handle. Names below describe
roles, not proposed stable API identifiers.

- **List:** account and filter identity; snapshot/update token; prepared rows; next-page state; applicable list counts.
  Account-switcher summaries remain independently available without opening every account list.
- **Conversation:** group identity; snapshot/update token; resolved header, self membership and capabilities; read state;
  selected draft; prepared timeline; opening/retained anchors and earlier/later page state.
- **Presentation identities:** include a bounded identity dictionary with each complete resulting window, covering
  every referenced identity. Clients make ordinary in-memory ID references, not secondary profile queries. Stable
  fallback entries cover profiles not yet available. The native screen adapter can expose direct conveniences.
- **Assets:** include typed unavailable/pending/ready/blocked/removed states and an opaque local access reference when
  ready. Descriptor availability is immediate; bytes are acquired asynchronously. Clients decode only visible content.

Recommend a complete bounded identity dictionary over repeating full identity objects on every historical message.
Profile refresh updates the current window through MDK; it must not require rewriting the full retained timeline.
Resolved conversation title/avatar remain explicit so clients do not infer peer/group selection from the dictionary.
If payload measurement shows dictionary handling adds more cost than it saves, change representation without changing
this completeness promise. Confirm concrete Swift/Kotlin ergonomics during the binding design.

## Recommended consistency rules

1. **Separate authoritative writes from presentation readiness.** A derived record never becomes authority for a
   permission, message, read marker or send outcome. Commands report durable acceptance according to their existing
   owners; a displayed capability is advisory and commands revalidate current state.
2. **Make lost work recoverable.** Where source and derived data share an account database, update cheap dependencies
   in the same transaction. Otherwise commit durable dirty/work evidence with the input change. Reuse existing dirty
   markers and repair machinery where they cover the dependency; do not assume process-local events survive a crash.
3. **Publish completed screen changes after commit.** A batch carries a token that lets the runtime reject stale
   updates and refresh the subscribed window. Specify coverage for every writer, including synchronous read/draft
   mutations that currently bypass worker commands; a worker queue alone is not a proof of serialization.
4. **Choose a local screen consistency boundary.** Source state may be ahead of completed derived work, but an emitted
   screen must be internally coherent and all identity references resolvable from its envelope. Do not promise one
   transaction across shared directory, account database and media filesystem. Missing assets remain explicit states.
5. **Directory changes require durable fanout.** Retain the last usable local presentation while newer accepted
   directory data propagates. Define source version, dependent accounts/groups, resume position and idempotent apply.
   C2 must demonstrate recovery if the process stops between shared-directory persistence and account refresh.
6. **Reuse bounded subscription recovery.** Attach before snapshot capture and reconcile buffered changes against the
   snapshot token; missed/overflowed updates result in an authoritative current-window refresh. Paging must be scoped
   to account, query and window generation, with stale-cursor recovery handled by MDK.
7. **Keep network work off screen readiness.** Local read/repair must be bounded. Interrupted rebuilds need a defined
   last-valid/fallback path, and must not expose deleted content while repair runs. Host shutdown closes admission and
   releases storage through existing terminal shutdown; pending maintenance resumes in a new runtime.

The first-slice plan specifies its revision representation, account/shared transaction boundaries and coalesced
profile-change records. Crash-safe asset writes belong to C7/C8. A revision number alone does not prove atomicity;
implementation tests must validate the documented boundaries before extending them to later views.

## Confirmed behavior and remaining source checks

- **Archive — confirmed:** an archived accepted conversation stays archived when ordinary new messages arrive.
  The user must explicitly restore it to the main list. Preserve this behavior across restart, sync and projection
  rebuilds. The inspected confirmation/fresh-invitation transitions are separate lifecycle behavior, not permission
  for an incoming message to clear the archive flag.
- **Name provenance:** current flagship direct creation is verified to use empty names, so derive automatic display
  without a new flag. Apply the conservative historical-name recommendation above and add an explicit legacy fixture
  before claiming support for a generated nonempty legacy name.
- **Lifecycle and cursor edges:** enumerate left/removed/disbanded and pending-operation capability states from current
  owners; define deletion of the opening unread anchor and filtered-window insertion/removal with example cases.
- **Assets:** choose a platform-usable local handle and specify protected storage/reference cleanup before C7/C8 start.
  This is engineering work under the agreed retention policy, not a reason to reopen that policy.

## First slice and C1 completion

Start with a resolved durable chat row through the existing runtime and native bindings: custom/group-versus-peer
selection, cached identity and fallback, profile/roster invalidation, and local reopen without a profile lookup.
Exercise the maintenance/recovery boundaries with this slice. Then add filtered list/window behavior and compose the
conversation contract using the same identity and update owners. Preview semantics, avatar bytes and retained media
keep their named child scopes and explicit dependencies.

The first-slice readiness gates are resolved in the linked plan. Remaining work is intentionally assigned:

- C4: final bounded list windows, composable filters, counts, cursors and unread/account-attention transitions.
- C5/C6: complete conversation response, identities, lifecycle/capability and anchor examples, accepted edits and system semantics.
- C7/C8: local asset handle, protected byte storage, retention, quotas and erasure details.
- C9/#938: adoption beyond list presentation, full non-chat native packaging assessment and broader device evidence.

These are not hidden prerequisites for the first resolved-row capability. Its P1-P3 implementation and P4 native
adoption each have explicit completion gates in the first-slice plan.

## Evidence inspected for this draft

The local MDK checkout remains `91221c86585387d0d029466728c86e765ed14150`; remote `master` was checked at
`788eaf0852442cb31311fd72d9dd6ea91c2642a6`. A follow-up read checked the relevant changes in account event recording,
source-retention finalization, list queries and UniFFI subscriptions. In particular, #1737 wraps normal event/timeline
projection and chat-row refresh in an account storage transaction, does the same for source-retention finalization,
and keeps accepted fanouts recoverable when finalization fails. Reuse these boundaries; the older inventory's separate
transaction observation applies to its pinned commit, not these newer paths. This was a focused diff read, not a complete
review of the merged PR or newly executed runtime tests:

- [Stored list query, rows, attention and direct reuse](../../../crates/storage-sqlite/src/chat_list.rs).
- [Archive mutation preserving worker state](../../../crates/marmot-app/src/client/mod.rs) and
  [confirmation transitions](../../../crates/marmot-app/src/groups.rs).
- [Runtime archive/attention operations](../../../crates/marmot-app/src/runtime/mod.rs).
- [Snapshot capture and current window/subscription ownership](../../../crates/marmot-app/src/runtime/subscriptions.rs).
- [Group snapshot with directory enrichment](../../../crates/marmot-app/src/runtime/commands.rs).
- [Existing draft ownership](../../../crates/marmot-app/src/drafts.rs).

Native entry-point sampling also found list subscription/row lookup and cached-identity calls in iOS `MarmotClient.swift`
and `ChatsListViewModel.swift`, and member-loading/archiving composition in Android `Controllers.kt`. That is a starting
consumer inventory, not a completed client migration audit.

Source versions for native sampling: iOS `190ac82c7f069cf49e05bb27a6552547a20c9ead`, Android
`3af7335263c9134503f04b061578a80a9b0ee346`. iOS list enrichment uses `GroupMembershipPageLoader` with a keyed-page read
and per-group fallback; its conversation view combines timeline subscription, group-state subscription and group snapshot.
Android keeps member/presentation caches for both title/avatar display and other consumers such as folders, shared-group
queries and profile actions. Remove only the display dependency when the first slice lands; do not delete the whole
roster cache until its other consumers have replacements.

### First resolved-row child: draft acceptance boundary

- Initial whole-row read/subscription returns the selected title/avatar descriptor from local storage, without another
  client lookup or network wait; missing profiles have deterministic typed fallbacks.
- Explicit names/images win independently; unnamed two-person groups use the other participant; a roster change cannot
  keep presenting a departed peer as the current peer. Group fallback and explicit custom-name cases have fixtures.
- Cached profiles existing before group creation and later accepted profile changes work with no active screen, across
  restart, and independently per account. Older profile input cannot roll back the accepted presentation.
- Directory-write/account-refresh interruption and projection-write/notification interruption recover without user
  refresh. Snapshot/update races cannot silently lose a change or apply an older generation over a newer one.
- Name/avatar-only updates preserve activity/order and unrelated unread/archive/draft state. Archiving stays explicit.
- Populated upgrade preserves existing rows, names, read intent and retained media; failed/interrupted upgrade is
  recoverable. No schema number is reserved until the implementation branch is based on current migrations.
- Swift/Kotlin can render resolved presentation directly. The C consumer obtains the complete result through one API
  while existing struct layouts/free rules remain compatible. Required command and record parity are checked.
- List display adoption removes its peer-selection lookup dependency; unrelated roster, folder, profile and narrow
  consumers remain supported. Avatar bytes and timeline semantics retain their separate implementation scopes.

This first slice provides resolved identity presentation, not the entire final filtered/paged list and conversation
contract. Its API must fit the complete contract before implementation; do not add an unrelated sidecar for each slice.
