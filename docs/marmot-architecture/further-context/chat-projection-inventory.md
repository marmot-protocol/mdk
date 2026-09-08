---
title: "Chat and conversation projection inventory"
created: 2026-09-07
updated: 2026-09-07
tags: [marmot, architecture, projections, chat]
---

# Chat and conversation projection inventory

Status: pinned source inventory plus agreed product direction; replacement API and engineering design remain to be finalized.

Parent design tracker: [#1742](https://github.com/marmot-protocol/mdk/issues/1742), which also contains the expanded
repository-wide related-issue audit. PR #1683 was closed in favor of that design effort; #1517 remains open.

Inspected MDK `master` at `91221c86585387d0d029466728c86e765ed14150` on 2026-09-07.
PR [#1683](https://github.com/marmot-protocol/mdk/pull/1683) is considered separately at
`b7af025a28acf485fa25377c7524771741c1b822`; its behavior is not included in the current-state tables.
The current-state map is a source inspection, not a complete audit of native clients. The separate released-binding
Android baseline is summarized in section 9. Since inspection, PR #1737 merged at
`788eaf0852442cb31311fd72d9dd6ea91c2642a6` with message-send query improvements and migration 0062; PR #1739 remained
open when this document was updated. Refresh current source and migrations before implementation.

The intended direction is an optimized, MDK-owned chat presentation API alongside useful lower-level APIs.
A complete response does not require one physical table, one SQL statement, or a separate database for every API.
Persist expensive derived state where it buys predictable reads; preserve the domain records and queries that support
other Marmot applications. Remove competing presentation ownership only after its replacement and consumers are known.

## 1. Existing persistent data and projections

The principal account-device database is `session.sqlite`. The tables below are related layers, not interchangeable
copies of a chat screen. Public directory data also lives outside that database.

| Layer | Stored representation and owner | Purpose and consumers | Current read/maintenance behavior |
| --- | --- | --- | --- |
| Engine/session state | MLS groups, retained history, application-event delivery/ack state, leave/disband state; engine and session storage | Protocol correctness, current membership, recovery, lower-level applications | Authoritative engine operations remain below the app presentation layer. A displayed projection cannot authorize a mutation. |
| Account group projection | `account_groups`, `account_group_app_components`; `StoredAccountGroup` → `AppGroupRecord` | Group profile, image/URL, components, routing, member count, local archive/invite/membership state; group queries and subscriptions | Saved through account projection deltas. `MarmotApp::groups` loads account projection state and overlays operational state. `group` currently filters that list; it is not a keyed SQL group read. |
| Direct-conversation membership index | `direct_conversation_members` | Peer-keyed existing-conversation lookup; records exact members for projected unnamed two-member groups | Maintained with account group projection. Legacy accounts have an explicit backfill/readiness path. This is useful independently of the chat-list display. |
| Raw app-event records | `app_events`; `StoredAppEvent` / `AppMessageRecord` | Inner app events, including reactions, deletes, edits, custom kinds; raw queries, subscriptions, replay and derived timeline inputs | `record_app_event_inner` updates raw input and affected timeline records in one transaction. Raw here means decoded app events, not raw encrypted relay traffic. |
| Materialized timeline | `message_timeline`, stream-start support; `TimelineMessageRecord` | Aggregated reactions/deletions, replies, edit-event rows, media/stream metadata, retention and invalidation; chat, tooling and agent readers | Incrementally reprojects affected rows and dependencies, but accepted edit-chain resolution remains client-owned. Supports explicit per-group rebuild. Group order uses canonical history; account-wide queries have wall-clock ordering. |
| Conversation read state | `conversation_read_state` | User read anchor and manual-unread intent | Durable input to unread derivation, not disposable presentation cache. Read mutations refresh the chat row transactionally. |
| Unread acceleration | `chat_list_unread_messages`, `chat_list_unread_ready_groups`, `chat_list_unread_dirty_messages` | Avoid scanning the whole unread window for each changed message | Timeline SQL triggers mark changed IDs dirty; incremental reconciliation or rebuild updates counts/first unread. Dirty/ready records also support recovery. |
| Chat-list projection | `chat_list_rows`, `chat_list_projection_meta`; `ChatListRow` | Cached group presentation, preview, unread state, activity ordering, archive/invite/membership fields | Durable but not a fully prepared screen row. Reads join/overlay other state and app code enriches preview sender names and attachment classification. Missing/stale projections can rebuild on a read. |
| Pin and mute state | `chat_pin_positions`, `chat_notification_settings` | User ordering and notification preferences | Joined into chat rows. Effective mute is time-dependent. Pin order is normalized for returned rows; subscriptions schedule finite-mute expiry refreshes. |
| Composer drafts | `message_drafts`, `message_draft_attachments`; full draft and metadata-only summary DTOs | One durable draft per group, reply target and ordered attachment bytes in the encrypted account store | Transactional save and consistent reads already exist. List summaries omit attachment BLOBs but load attachment summaries per draft. Separate from `chat_list_rows`; current save/delete methods do not refresh a chat row or emit a dedicated draft subscription update. |
| User directory | Per-account `app-cache.sqlite3` plus public directory in `shared.sqlite3` | Cached names, pictures, profile metadata, relay lists, KeyPackages and identity queries | Accepted directory records are written to shared storage and account caches. Read selection reconciles cached/shared records. The bounded identity API is local-only, but internally still resolves each requested ID. |
| Legacy app projection | `LegacyAccountProjectionDb`, old `app.sqlite3` | Import of existing installations into account storage | Opened by `migrate_legacy_account_projection_if_needed`, gated by an import marker. It is not the normal live chat-screen database. Preserve migration support until a deliberate compatibility decision. |

Sources: [account projection](../../../crates/storage-sqlite/src/account_projection.rs),
[app group types](../../../crates/marmot-app/src/groups.rs),
[timeline storage](../../../crates/storage-sqlite/src/timeline.rs),
[chat-list storage](../../../crates/storage-sqlite/src/chat_list.rs),
[unread migration and triggers](../../../crates/storage-sqlite/src/migrations/0059_chat_list_unread_membership.rs),
[directory methods](../../../crates/marmot-app/src/directory/methods.rs),
[draft storage](../../../crates/storage-sqlite/src/message_drafts.rs),
[app query/lifecycle wiring](../../../crates/marmot-app/src/lib.rs),
[legacy importer source](../../../crates/marmot-app/src/projection.rs).

## 2. Chat-list API and field map

| Surface | What it returns today | Boundary relevant to a complete chat screen |
| --- | --- | --- |
| `chat_list(account, include_archived)` | All matching hydrated `ChatListRow` records, pin order then activity order | One FFI call, but only archive inclusion is configurable. No list paging, search, unread-only or kind filter in `ChatListQuery`. |
| `chat_list_row(account, group)` | One hydrated row or absence | Keyed row SQL; app readiness/projection checks and enrichment still run. Useful for targeted consumers. |
| `subscribe_chat_list` | Initial rows plus typed row upsert, removal, or full replacement | Initial broadcast subscription is installed before snapshot read. Pin/archive changes replace the list; ordinary projection events can deliver rows directly; group events cause refreshes. |
| `ChatListSubscription::next_update` | Typed update including removals/replacements | Current suitable contract for maintaining a list. It has triggers, but no public durable projection revision/resume cursor. |
| `ChatListSubscription::next` | Compatibility row-only stream | Drops removals and flattens replacements; explicitly insufficient for correct removal/replacement semantics. Both methods consume the same stream. |
| `account_unread_summary` | Per-account unread and attention aggregates | SQL aggregate over the same chat projection, not another stored list. Skips unavailable accounts with a warning. |
| `existing_direct_conversation` | At most one reusable conversation for a peer | Uses the member index and MDK reuse rules. Has explicit index-not-ready behavior. Keep for callers that do not need a full list. |
| `groups` / `visible_groups` / `subscribe_chats` | `AppGroupRecord` records | Lower-level group/component projection, despite the subscription's chat-oriented name. No last-message/unread screen row. |

The synchronous list methods execute work on the caller; subscription snapshot loading is dispatched off-thread.
UniFFI subscription `snapshot()` consumes its initial snapshot. It is not a repeatable live-state getter.

| Row information | Current source | Prepared for direct rendering? |
| --- | --- | --- |
| Conversation identity, archive/invite state, membership | Durable account/chat projection | Mostly; state is present as typed fields. |
| Title / `group_name` | Group-derived chat projection | No resolved peer title for unnamed direct chats. Hosts still need a presentation policy and peer/profile evidence. |
| Avatar | Group avatar URL or encrypted group-image material | No resolved direct-peer avatar. Image download/decoding is a separate asset path. |
| Last preview text, kind, timestamps, deletion and delivery state | Durable chat projection derived from timeline | Substantial preparation exists. Structured system-message/localization policy is still relevant; this is not a universally final display string. |
| Preview sender display name | App read-time directory lookup | Returned after hydration, not stored in the chat row. Current profile ingestion does not independently wake chat-list subscribers. |
| Attachment kind/count | App read-time parsing of internal persisted media JSON | Returned, but computed on reads. Internal `media_json` is not exposed in the row bindings. |
| Unread, mentions, first unread and read anchor | Read state plus unread projection | Already MDK-owned; do not reimplement in clients or replace with a second counter system. |
| Pin order and effective mute | Joined preference tables plus current time | Returned; timed changes require scheduling even when no relay event arrives. |
| Draft preview / composer intent | Separate durable draft-summary API | Not included in the chat row. Define whether a draft replaces the normal preview, affects ordering, and clears after a successful send; preserve unsent text and attachment bytes. |
| Conversation kind | Group name plus persisted member count | Classified in MDK, but currently tells the host the kind without resolving all display consequences. |
| Leave/disband/lifecycle | Engine-owned records and derived overlays | Included in the returned row, not all duplicated into `chat_list_rows`. |

Sources: [row/query definitions and SQL](../../../crates/storage-sqlite/src/chat_list.rs),
[`chat_list`, `hydrate_chat_list_rows`, `account_unread_summary`](../../../crates/marmot-app/src/lib.rs),
[FFI commands](../../../crates/marmot-uniffi/src/commands/chat_list.rs),
[FFI row fields](../../../crates/marmot-uniffi/src/conversions/chat_list.rs),
[runtime subscriptions](../../../crates/marmot-app/src/runtime/subscriptions.rs),
[FFI subscription compatibility](../../../crates/marmot-uniffi/src/subscriptions.rs).

## 3. Individual-conversation APIs

There is no current single subscription returning a fully prepared conversation header, capabilities, initial timeline,
and all associated presentation updates.

| Surface | Existing behavior | Remaining composition |
| --- | --- | --- |
| `group_conversation_snapshot` | One account-worker command captures group record, members and MLS state. Cached member names are added after the response. UniFFI derives `management_state` from the exact returned details. | No timeline, chat-list read/unread row, resolved direct-chat header, or member avatars. It is a live worker snapshot, not a separate stored screen snapshot. Directory names are optional enrichment outside the worker capture. |
| `group_details` | Returns group, member details and MLS state through the same worker snapshot path | View of the same data, not another materialized database projection. |
| `group_management_state` | Computes permissions/action conditions from group details | Policy is already partly centralized. This does not establish a complete composer/message-action contract. Actual mutations still enforce current authority. |
| `group_roster` | Typed members, self/admin status, names, epoch/revision and lifecycle | Useful independent roster contract. No need to force its callers to load a timeline. |
| `group_members`, `group_member_ids_page`, `group_mls_state` | Lower-level worker reads; bounded multi-group member page | Preserve for non-screen uses. The member page is not a fully prepared chat-list projection. |
| `subscribe_group_state` | Initial and changed `AppGroupRecord` | Does not stream the complete roster/management snapshot. Current backing `group` read loads and filters the group list. |
| `timeline_messages` | Materialized `TimelinePage`, group or account-wide, search and cursor options | Synchronous FFI one-shot API is documented for diagnostics/tooling, not chat scrolling. |
| `subscribe_timeline_messages` | Initial materialized page and a runtime-owned bounded live window with bidirectional pagination | Already owns ordering, deduplication, scroll-window preservation and refresh after lag. Search windows refresh rather than applying raw projection deltas directly. |
| `TimelineMessagesSubscription::next` | Resulting authoritative window | Convenient prepared page; do not make each client reimplement window management. |
| `TimelineMessagesSubscription::next_update` | Typed projection/snapshot update | Lower-level incremental consumption. No combined header/profile update contract. |
| `messages` / `subscribe_messages` | Raw decoded app events with group/kind/limit querying on the one-shot path | Deliberately distinct from folded timeline semantics; valuable for custom application events and tools. |
| `timeline_message`, `message_by_id`, `reaction_target` | Targeted Rust/runtime reads of materialized or raw records | Narrow consumers should retain these. Not every Rust helper has an identically named FFI wrapper. |
| `message_drafts` / `message_draft` | Metadata-only draft list versus one full composer draft with attachment bytes; save/delete commands | Current host owns clearing empty/sent drafts. Include the selected draft's text, reply target and bounded attachment descriptors in the conversation-open design; decide when full bytes are loaded. Multiple saved drafts are a separate extension (#1520). |
| `list_media` / `download_media` | Typed media references built from raw message queries; a separate download operation | `list_media` has an optional message limit but no attachment cursor and is not a canonical paginated attachment-gallery projection (#1448). Gallery history and download progress need their own bounded contracts. |

Sources: [group types](../../../crates/marmot-app/src/groups.rs),
[`group_conversation_snapshot` worker dispatch](../../../crates/marmot-app/src/runtime/commands.rs),
[`group_roster_session`](../../../crates/marmot-app/src/client/mod.rs),
[FFI group builders](../../../crates/marmot-uniffi/src/commands/group.rs),
[FFI group contract](../../../crates/marmot-uniffi/src/conversions/group.rs),
[timeline command](../../../crates/marmot-uniffi/src/commands/timeline.rs),
[raw message command](../../../crates/marmot-uniffi/src/commands/message.rs).

Additional sources: [draft ownership](../../../crates/marmot-app/src/drafts.rs),
[draft bindings](../../../crates/marmot-uniffi/src/commands/draft.rs),
[media commands](../../../crates/marmot-uniffi/src/commands/media.rs).

### Timeline preparation already provided

Persisted timeline rows include message content, reply previews, reaction summaries, deletion/invalidation state,
source epoch, retention deadlines and media/agent-stream metadata. UniFFI adds parsed Markdown, structured group-system
events and validated downloadable media references, including reply attachment references. This work is significant and
should be reused. A subscription-local conversion cache retains only its current window and avoids reconverting unchanged
records; it is an optimization, not competing durable truth.

Edit handling is incomplete: kind-1009 events and their targets are reprojected, but that does not mean the target row
contains the accepted replacement text. The current `edit_message` contract explicitly leaves edit-history resolution
to hosts. Existing issue [#957](https://github.com/marmot-protocol/mdk/issues/957) tracks moving that resolution into
MDK and keeping timeline content and chat-list previews consistent without changing activity order.

The current `TimelineMessageRecordFfi` still exposes sender IDs without sender display names/avatar presentation. Reply
authors, reaction participants, mention references and group-system actor/subject identities can also require identity
resolution. Timeline delivery is expressed through source ID, direction and invalidation fields, while chat previews have
a dedicated delivery enum. The contract should decide which semantics to unify without claiming relay acceptance proves
recipient receipt. Localization remains a host concern unless an explicit localization interface is designed.

Sources: [timeline storage DTOs](../../../crates/storage-sqlite/src/timeline.rs),
[timeline conversion](../../../crates/marmot-uniffi/src/conversions/timeline.rs),
[conversion cache](../../../crates/marmot-uniffi/src/subscriptions.rs),
[cached identity API](../../../crates/marmot-uniffi/src/commands/directory.rs).

## 4. Current update, consistency and recovery map

| Change / lifecycle | Existing route | Consequence for the proposed screen contract |
| --- | --- | --- |
| Received app event | `client/sync.rs::project_received_message` → `record_account_app_event_at` → raw event/timeline transaction → `app_projection_update` → chat-row refresh → `RuntimeProjectionUpdate` | Timeline and chat-list changes already share an outgoing update envelope. The normal timeline write and chat-row refresh are separate storage transactions; do not assume the envelope proves one atomic commit of every dependency. |
| Local send and later delivery/failure | Local event projection plus source-retention finalization/invalidation → timeline changes and chat refresh | Reuse existing send lifecycle; screen state must not invent a second send/delivery authority. |
| Group creation | Account delta plus created chat row commit in one storage transaction; detailed create returns the row | Existing model for returning committed local presentation immediately. Other dirty groups retain a stale marker. |
| Roster/group profile/image/component changes | Update account group projection; ordinary delta saves mark the account chat projection stale; group events route subscriptions to refresh rows | Maintenance is partly event/read-driven. A complete screen projection needs explicit dependency updates even with no active subscriber. |
| User profile changes | Accepted profile → shared/account directory caches and directory-sync rebuild request | Current runtime chat/timeline event routing contains no profile-presentation change. A later read may pick up the new name, but independent live presentation refresh is missing. |
| Read marker/manual unread | Transactional read-state mutation and chat-row refresh, runtime projection notification | Existing central ownership to retain. |
| Draft save/delete | Transactional draft/attachment write through app draft methods | No current combined screen invalidation route. Include draft changes and send/clear semantics when defining the dependency matrix. |
| Pin/archive | Durable preference/state changes, subscription full-list replacement | Filter membership and ordering can change together; row-only legacy streams lose necessary semantics. |
| Mute expiry | Stored deadline plus per-chat-list-subscription timer | Time is an input. Reopen must calculate effective state; persisted booleans alone become stale. |
| Retention, deletion, convergence invalidation/revalidation | Targeted raw/timeline changes and dependency repair; secure prune also repairs relevant chat state | Projection design must preserve erasure, tombstones and canonical order; rebuild is not permission to revive pruned content. |
| First open/restart | Account storage migration/import/ensure; chat projection completeness check; optional rebuild | A cache-backed API can still do maintenance on first read. Existing warm/stale sets are process-local; unread dirty/ready/version state is durable. |
| Subscriber lag | Timeline refreshes its current window; chat list reloads and reconciles | Good existing recovery primitives. Broadcast updates are process-local, not a durable resumable change stream. |
| Snapshot plus updates | Broadcast receiver attached before initial reads; typed updates and row fingerprints/window generations | Avoids a simple subscribe-after-read gap, but does not provide one public revision spanning directory, roster, list and timeline. Define that boundary explicitly before composing a screen. |

Sources: [incoming projection](../../../crates/marmot-app/src/client/sync.rs),
[local projection](../../../crates/marmot-app/src/client/projection.rs),
[`record_account_app_event_at`, `app_projection_update`, readiness and import](../../../crates/marmot-app/src/lib.rs),
[runtime event publication](../../../crates/marmot-app/src/runtime/account_worker.rs),
[event routing](../../../crates/marmot-app/src/runtime/event_routing.rs),
[subscription recovery](../../../crates/marmot-app/src/runtime/subscriptions.rs).

This is a map of the inspected paths, not proof that all interrupted writes lose or preserve screen consistency.
The unread dirty triggers, projection completeness checks, application-event acknowledgements and existing repair paths
must be considered together in a dedicated failure/restart test matrix. Likewise, a local connection lock should not be
described as a cross-database snapshot transaction.

## 5. Preserve, consolidate, and investigate

| Disposition | Candidates | Reason |
| --- | --- | --- |
| Preserve useful foundations | Raw app events, materialized timeline, account components, roster APIs, keyed message and peer lookup, cached identity APIs | Different consumers need different shapes. `wn-agent` already uses targeted/materialized timeline reads without the native chat-screen DTOs. |
| Evolve into chat fast path | Existing durable chat rows, timeline window/subscription machinery, group snapshot and action-policy helpers | Much of the hard work already exists. A complete contract should compose/reuse it before introducing parallel screen stores. |
| Consolidate presentation ownership | Direct/group title/avatar selection; sender/reply/system-actor presentation; shared display fallbacks; presentation invalidation | These are responsibilities for a common MDK presentation layer, not repeated client or binding-specific reconstructions. |
| Treat as compatibility surface | Row-only `ChatListSubscription::next`; overlapping group/details convenience methods | A flawed event shape is a deprecation candidate; a cheap wrapper over shared implementation is not automatically redundant. Audit consumers before removal. |
| Keep until migration policy changes | `LegacyAccountProjectionDb` importer and fixtures | Legacy code supports upgrades; its presence does not mean a second live presentation database should be maintained. |
| Investigate independently | Account/shared directory duplication and selection rules; read-triggered rebuild costs; all-groups work in a single-group query | Possible simplifications/performance work, but none is justified for removal solely by introducing screen projections. |
| Retain bounded ephemeral optimization | Timeline window and FFI conversion cache; transient stream watches | They hold window/render/transport work, not durable user intent. Durability of screen state does not make these unnecessary. |

Concrete non-screen consumer: [agent timeline reader](../../../crates/agent-connector/src/timeline.rs).
C mirrors the UniFFI surface rather than implementing an independent projection pipeline; preserve ABI compatibility
when evolving it ([C architecture](../../../crates/marmot-c/AGENTS.md)). Rust/CLI/agent callers also need access to any
common presentation policy intended to be MDK-owned; avoid making UniFFI its sole owner.

External integration evidence: [#938](https://github.com/marmot-protocol/mdk/issues/938) describes Whistle's custom
location payloads and host-owned transport. Useful low-level Rust APIs do not establish a complete supported low-level
native binding surface. Decide whether that surface belongs beside MarmotKit or in separate bindings; Jeff's existing
comment explicitly leaves that choice open. Do not route users back to protocol-v1 bindings as a compatibility solution.

## 6. How PR #1683 fits

At the inspected PR head, the proposal adds a durable direct-peer side projection to chat rows: peer identity, display
name, avatar URL, profile timestamp, schema version and Absent/Current/LastKnown/Invalidated state. It hydrates from the
existing local directory during reads, fans profile changes into account stores, introduces presentation notifications,
and adds subscription rereads/retries. The C ABI uses an additive sidecar accessor rather than changing the legacy row
layout. Its avatar field is a URL reference, not persisted decoded image pixels.

This addresses a real missing dependency, but does not complete the general screen contract: existing group title/avatar
fields and optional direct-peer fields still coexist, the client still has to select presentation, and a C caller needs
the sidecar read. It does not add rich list filters or a combined conversation-screen subscription.

Its tests for reopen, profile updates, peer replacement and account isolation are valuable requirements evidence. The
exact schema/state model and migration should be reassessed against the complete chat-row contract, rather than made
fixed constraints for that design. PR #1683 was subsequently closed in favor of #1742; its implementation is not part of the source baseline.

## 7. Remaining engineering decisions

The [C1 reference draft](chat-screen-contract-draft.md) maps field ownership and broader consistency requirements.
The [first implementation plan](chat-presentation-first-slice.md) now resolves the C1 gate for the initial C2/C3 slice
in #1517, attached as the first implementation child of #1742. Later detailed decisions remain with their children.

The product discussion in section 9 supersedes the initial design-question list. The concise plan and proposed child
boundaries are maintained in [#1742](https://github.com/marmot-protocol/mdk/issues/1742). Remaining decisions are:

1. Field ownership: authoritative source, persisted/joined/transient derivation, invalidation trigger, and transactional
   versus durable deferred maintenance, including directory fanout, drafts and time-dependent state.
2. Consistency: revision/readiness boundaries, initial snapshot and stream handoff, lag refresh, window anchors,
   rebuild/versioning and interruption/restart behavior across account/directory stores and host lifecycle.
3. Representation and edge cases: embedded identity versus complete page dictionary, generated/custom-name provenance,
   self-only/group fallbacks, lifecycle/action states and aggregate account status. The explicit-restore archive rule
   is confirmed below.
4. Paging and assets: bounded windows, stable filter/cursor/count semantics, disappearing unread anchors, local asset
   handles, protected bytes, shared references, retries, partial-file cleanup and erasure.
5. Compatibility and acceptance: actual client and narrow-API consumers, supported non-chat native binding route,
   migration/deprecation boundaries, representative fixtures and separate MDK-only versus whole-client performance gates.

Resolve these for the first useful slice before implementing it; later child details can be refined within the same
contract. Do not turn every adjacent issue into an up-front dependency or a new projection infrastructure requirement.

Existing source tests worth retaining include `created_group_projection_and_chat_list_row_commit_atomically`,
`chat_list_reads_cached_projection_without_rebuilding`, `conversation_kind_uses_durable_current_roster_projection`,
`visible_activity_survives_read_metadata_membership_and_secure_prune_updates`, the unread dirty/rebuild tests,
`chat_list_snapshot_reconciliation_updates_changed_rows_and_removes_missing_rows`,
`pin_order_changes_are_sent_as_one_atomic_snapshot`, and the timeline window pagination/ordering tests. These names
were located in source; they were not executed for this documentation inventory.

## 8. Existing issue alignment

The following issues were read while checking the proposed planning structure on 2026-09-07. They should be linked and
reconciled with a design tracker before new implementation children duplicate their scope. These are existing issue
requirements, not a statement that their proposed behavior is implemented or approved by this inventory.

| Existing issue | Relationship to the screen contracts |
| --- | --- |
| [#1517 — Persist direct-chat peer presentation](https://github.com/marmot-protocol/mdk/issues/1517) | Preserve the cold-start requirement and Android dependency. Revisit its prescribed separate peer fields and freshness states against the complete resolved chat-row contract. |
| [#956 — Authenticated group-system subjects on chat-list preview FFI](https://github.com/marmot-protocol/mdk/issues/956) | Reuse provenance and actor/subject requirements. Its instruction to leave profile lookup in clients needs reconciliation with the new optional chat fast path; the lower-level authenticated event should remain presentation-independent. |
| [#957 — Resolve kind-1009 edits in timeline and chat-list records](https://github.com/marmot-protocol/mdk/issues/957) | Reuse shared accepted-edit resolution and non-activity preview-update requirements. This is a substantive missing semantic projection, not simply a binding omission. |
| [#1363 — Typed account-wide local message search](https://github.com/marmot-protocol/mdk/issues/1363) | Coordinate search/filter semantics and source projections. Message-level search is distinct from filtering conversation rows and should not be silently absorbed into that work. |

## 9. Product decisions from the contract discussion

These decisions were agreed with Jeff on 2026-09-07 after opening #1742. They describe the intended contract, not
implemented behavior. Before creating implementation children, verify each item against the current code and retain
matching implementations. The device baseline below uses released bindings, separately identified from this source map.

### Chat list

- One list per account, with a separate lightweight account-switcher unread summary. The first response is a bounded
  page of complete rows with a continuation cursor. MDK owns ordering, filter membership and live changes.
- Row contents: stable conversation identity; resolved title/avatar and fallback; typed prepared preview, sender,
  attachments/system event and delivery state; activity timestamp/order; unread/mention/manual-unread state; pin, mute,
  archive and draft summary; pending-invite/membership/lifecycle state and available row actions.
- All conversations are groups. An explicitly chosen group name takes precedence at any size. An unnamed two-person
  group, or one with only an automatically generated default name, uses the other person's display name. Larger groups
  use their meaningful group name or a group fallback. Peer-profile absence uses a stable peer fallback.
- Group images take precedence independently of group names. Without a group image, two-person groups use the other
  person's avatar; larger groups use a group fallback. Reliable default-versus-custom name provenance and the exact
  self-only/unnamed-group fallback remain engineering details to specify.
- Draft text/attachment summary replaces the message preview with a typed Draft indication. It does not suppress unread
  badges or change activity time/order. Clear the submitted draft only on durable send acceptance; retain it on failed
  acceptance. Subsequent delivery failure is timeline retry state. A late completion cannot erase a newer draft.
- New messages, including durably accepted local sends, and membership changes affect activity order. Edits, reactions,
  profile/name/avatar changes, read-state changes and delivery updates do not. Deleting/expiring the latest message
  reveals the previous eligible preview while preserving the activity timestamp and position.
- Pending invitations remain alongside accepted conversations. With messages, show the latest eligible preview;
  otherwise supply a typed invitation placeholder for client localization. Invitation state is independent of preview
  content so the client can always distinguish the row visually.
- Suppress pending-invite unread counts and mention badges until acceptance. Acceptance enables normal unread rules;
  it does not mark messages read. Viewing messages advances the normal read marker.
- Archived conversations have a separate filtered view and are excluded from the main list. New messages do not
  restore an archived accepted conversation: the user must explicitly restore it. Preserve this rule across restart,
  sync and projection rebuilds.
- Unread and Mentions are composable filters, including combinations with archive state. Muting suppresses notifications
  but preserves unread counts, mention badges and filter membership; expose effective mute state and expiry.
- Account-switcher attention includes muted conversations but excludes archived conversations and pending invitations.
  Manual unread independently activates attention and the Unread filter without inventing message or mention counts.
  Current `set_chat_manually_unread` and its regression tests already cover the durable independent flag and summary
  contribution. Current `account_unread_total` explicitly includes pending invitations as attention, so excluding them is
  a targeted behavior change, not existing parity. The current native list query does not yet implement these filters.

### Conversation, identities and localization

- One initial response includes resolved header, current membership/invitation state and capabilities, read/unread
  state, selected draft and a prepared timeline window. Open around the first unread message when present; otherwise
  around the latest message. Supply anchors and paging in both directions.
- Include member count, local membership/permissions and the identity presentation needed for all returned content:
  senders, reply authors, mentions and system-event actors/subjects. Load the complete roster separately for group details.
- Every page or live update includes any newly needed identity presentation. Profile changes refresh visible
  presentation through MDK updates, without external per-row client lookups. Embedded fields versus a page-local identity
  dictionary remain a representation decision.
- Serve valid cached presentation immediately across restarts; otherwise return stable fallback presentation. Background
  profile retrieval must not block screen readiness. Clients own localization, image decoding, layout and styling;
  MDK supplies typed events and structured values with resolved identities.
- MDK owns durable validated avatar image storage, refresh and eviction, exposed through usable local asset references.
  Avatar cache policy is distinct from the retained attachment policy below.

### Retained attachments

- In accepted conversations, receipt schedules prompt background acquisition independent of visibility. Persist enough
  work to retry/resume after interruption. Verify successful downloads and retain the required media secrets; repeated
  render requests should reuse the stored media rather than initiate another remote download.
- Return attachment descriptors, availability and local access handles with the message. Outstanding acquisitions emit
  updates when usable. Clients decode/load local bytes when content is visible. Share in-flight acquisitions and permit
  retries of failed attempts; “download once” does not mean forbidding recovery of an incomplete transfer.
- Acquired media remains until the associated message is deleted, expires, or the user explicitly removes local media.
  Required secret retention/retirement must follow the appropriate message-reference policy. Do not claim a universal
  single-download protocol rule: current MDK caches versioned media epoch secrets while retained references require them.
- Storage pressure pauses acquisition with a clear recoverable storage-blocked state. Do not silently evict retained
  attachments; resume acquisition when space becomes available.
- Pending invitations do not automatically acquire attachments until acceptance. Their metadata remains visible; an
  explicit user request can acquire an attachment before acceptance.
- Remember explicit local removal so reopening, syncing or background repair does not automatically reacquire those
  bytes. Keep metadata and require an explicit download-again action. Erasure, shared-blob references, partial-file
  cleanup, account scope, quotas and the exact local-handle API require concrete implementation contracts.

### Maintenance, recovery and compatibility

- Maintain durable projection/identity/media work whenever the runtime runs, without requiring an active screen.
  Host suspension/shutdown can pause execution; durable pending work resumes on restart. Screen opening consumes latest
  local state and does not await network catch-up.
- Couple initial snapshots with subscriptions. On missed updates, MDK supplies a refreshed consistent current window,
  preserving the anchor where possible. Clients do not replay raw events to reconstruct a screen. Exact revisions,
  transaction boundaries and cross-store consistency still require engineering design.
- Preserve a separately documented useful lower-level API for non-chat consumers with shared implementation. Make
  disabling chat projection/automatic acquisition optional only where straightforward; do not introduce a substantial
  configuration/lifecycle system solely to support that switch. Packaging as separate native bindings remains undecided.
- Migrate consumers in stages: add complete contracts, adopt them in clients, then remove redundant presentation caches
  and obsolete APIs after accounting for consumers. Retain useful narrow queries and inexpensive wrappers.

### Workload and measurement proposals

Jeff identified iOS and Android as the flagship clients, with realistic large accounts having tens to low hundreds of
conversations and histories from approximately 40 to 5,000 messages. Proposed fixtures are 20 × 40 (small), 75 mixed
histories of hundreds (typical), 150 mixed histories totalling about 100,000 messages (large realistic), and 150 × 5,000
(stress). The suggested p95 thresholds of 500 ms cold local readiness, 50 ms warm list, 100 ms conversation/page and
100 ms committed-change propagation remain provisional proposals pending baseline evidence. They are not measured
results or committed cross-device release gates.

The first authorized device is a Pixel 9a on Android 17/API 37. The existing Android performance toolkit uses optimized,
non-debuggable dev APKs and real UI journeys. The initial baseline uses Android source
`3af7335263c9134503f04b061578a80a9b0ee346` and packaged MarmotKit 0.9.18 source
`f734b31176ad628d5e5dfcb047f80e4ec7bb826c`; it does not measure the unimplemented screen contract or establish iOS parity.

The small Pixel baseline completed six benchmark cases and 80 measured iterations. Median whole-client timings were
1,480 ms online cold first display, 1,353 ms offline cold first display, 958 ms first conversation open after restart,
and 241 ms warm conversation reopen. The primary fixture has 20 two-person groups and 800 generated outgoing messages;
a generated peer is a second account in the same dev store. These timings include native startup/UI navigation/rendering
and are not MDK-only query latency. This is before/after evidence for the projection effort, not a new startup workstream.
Large histories, incoming/unread anchoring, assets, deletion/expiry, low storage and iOS remain unmeasured by this baseline.
Exact fixture/APK provenance, benchmark JSON and traces are retained locally, not published as issue attachments.
