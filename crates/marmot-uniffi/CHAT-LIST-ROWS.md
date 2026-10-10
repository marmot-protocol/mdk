# Complete chat-list row previews and actions

This is the **MDK 0.10.3 C3 follow-up to MDK 0.10.2**. It adds fields to
`PresentedChatRowFfi` (Swift/Kotlin) and `MarmotPresentedChatRow` (C). Ship matching
generated source, native library and C header together; existing record layouts
are not binary-compatible. No database migration or new draft store is required.

## One row, one selected preview

Use `preview` from the returned row in bounded chat-list windows, presented-list
snapshots/updates and keyed presented-row reads:

| Selection | Render |
| --- | --- |
| `Draft` | A client-localized draft label plus the supplied text and attachment kind/count. |
| `Message` | This same row's existing `row.last_message`, including prepared sender/system/attachment content. |
| `Invitation` | A localized invitation placeholder (there is no latest message or meaningful draft). |
| `Empty` | Your localized empty-conversation treatment. |

Draft selection wins when the saved draft has non-whitespace text or attachments.
Whitespace-only and reply-target-only drafts do not replace the message preview.
The composer retains the exact saved content/reply: selecting a list preview
neither clears nor rewrites it. Draft text is trimmed and limited to 1,024 Unicode
scalar values; `text_truncated` tells clients when the preview is shortened. Attachment
summaries contain a count and Photo/Video/Audio/File/Mixed kind, never bytes,
filenames, URLs, waveforms or thumbnail payloads. Draft text is plain preview text.

`row.pending_confirmation` remains independent of preview selection: a pending
invitation with a message shows that message **and still needs an invitation
indicator**. Selecting a preview does not accept an invitation or change badge policy.
Clients own localization, styling and icon selection.

The selected row and draft metadata are read in the same local database snapshot.
Only returned groups' drafts are read; attachment plaintext is never loaded. Text
and summary output are bounded, although SQLite must inspect the selected draft's
text and attachment metadata to trim/count them. Work is independent of unrelated
account drafts and attachment BLOB sizes. No engine hydration or network is needed.

Both list subscription APIs attach draft invalidations before their initial read.
Save, delete and revision-bound durable send acceptance refresh the authoritative
window; lag recovers from storage. A newer draft edit survives an older send.
Use the live handle’s sequence for complete row updates: `presentation_version`
still versions selected identity, not drafts or unread state. Draft changes do not
move chats, change pin order, alter filters or create unread activity. A draft outside a retained window is picked up when that row is paged in.
Continue using the revisioned conversation draft API for editing and sending; do
not reconstruct a composer from the shortened list preview.

## Pending-send draft presentation (unreleased)

`PresentedChatRowFfi.draft_version` is an optional opaque `ChatListDraftVersionFfi`
object holding device-local store/group/revision metadata,
read in the same transaction as the selected preview. It is also returned for
empty/deleted drafts, so a host can observe cleanup without comparing text.
Missing metadata means no comparable revision is available, not successful
cleanup. Never decode, log, persist or transmit this version.

Capture the selected composer's `MessageDraftRevisionFfi` before accepting a
send. `includesChatListVersion(row.draftVersion)` returns true only when the
row's version belongs to the same account store and group and is no newer than
that captured revision. It returns false for a newer edit (even identical text),
a recreated draft or another store/group. A true result does
not authorize deletion: retain recovery until durable acceptance, then use
`clearMessageDraftIfRevision` with the captured revision. Never reselect an
unrelated newer revision for cleanup.

This enables a temporary host presentation handoff to a pending outgoing
preview while Markdown preparation or native cleanup is delayed. The host must
fence that presentation by its accepted editor generation, restore it on a
known pre-acceptance failure, and immediately honor newer edits. MDK remains the
sole persisted draft authority. The metadata does not change preview selection,
pins, ordering, unread state or delivery semantics. It does affect update emission:
a save with identical text still advances the draft revision, so the presented
list subscription emits a complete replacement snapshot for that change.

Adoption requires matching regenerated bindings and native libraries. C adds
a nullable row-owned `MarmotChatListDraftVersion` handle as `draft_version` in
`MarmotPresentedChatRow`; parent deep-free releases it. The handle has no foreign
constructor, getters or draft-mutation capability. Borrow that handle and a live
`MarmotMessageDraftRevision` for
`marmot_message_draft_revision_includes_chat_list_version`; its required `uint8_t`
output is cleared on errors. Rebuild against the matching header/library.
No schema migration or workspace version bump is required.

## Disappearing-message previews (0.10.4)

`ChatListMessagePreviewFfi` now carries `retention_seconds` and
`retention_expires_at` (`retentionSeconds` / `retentionExpiresAt` in Swift/Kotlin).
These are the selected message's pinned source-epoch decision, just like timeline
records. Raw rows, presented rows and bounded windows expose the same fields.
No database migration is needed; install matching regenerated bindings and native
libraries. C's `MarmotChatListMessagePreview` adds `has_retention_seconds` /
`retention_seconds` and `has_retention_expires_at` / `retention_expires_at`; rebuild
consumers with the matching generated header because the record layout changes.

When rendering a message preview, hide its content once the current Unix time in
**seconds** is greater than or equal to the supplied finite expiry. Re-evaluate
on foreground/resume and at the deadline while the list is visible: the passage
of time alone does not emit a chat-list update. Apply this only to the message
selection, not a separately selected local draft or invitation.

- Missing duration means an unknown/legacy decision: safely retain it.
- Zero duration means retention was explicitly disabled for that message.
- Missing expiry means no finite deadline, even with a positive duration (timestamp
  overflow). Never reconstruct one from `timeline_at` or the current group policy.

For example, after a change from five minutes to thirty seconds, the newer
message's expiry does not change the older message's five-minute decision.
These fields allow hiding the expired preview before periodic pruning. They do
not select an older surviving message automatically; an expired selected message
can be rendered as an empty preview until an authoritative replacement arrives.
Keep the row itself, ordering and unread state authoritative to MDK.

## Complete fixed-view selection

`captureChatListSelection(accountRef, view)` captures every eligible ID in one
Chats, Unread, Archived or Left view, independently of the screen's 50/200-row
window. The frozen order/count holds only IDs; capture and action revalidation
are O(eligible IDs), without profile, roster or message-body hydration. Pending
base preparation returns `ChatPresentationNotReady`, never a complete partial count.

Call `count()` for the complete count/current revision, then `page(revision,
offset, limit)` for at most 200 IDs. New messages, order changes and late chats
do not expand the captured intent. `deselect(revision, groupIdHex)` removes one
ID; unknown IDs leave intent unchanged. A changed selection supersedes old pages
with `ChatSelectionStale`. `revalidate(revision)` removes no-longer-eligible IDs
and always advances the revision; use only new-revision pages for the action.
Each mutation still checks current authorization and preconditions. Revalidation
is not an atomic permission grant, and the handle executes no bulk mutations.

Commands serialize on the handle. Cancellation before queued admission prevents
its local intent change; an admitted change can complete after caller cancellation.
Read the current count/revision before retrying a cancelled operation. `close()`
is idempotent and terminal; explicit close, account reset, shutdown or dropping
the final object releases the selection and discards pending read results. A
closed/reopened/foreign account store cannot reuse old intent. Hosts must close
when switching selection context and never log or persist returned IDs.

C has `MarmotChatListSelection` and matching capture/count/page/deselect/
revalidate/close/free calls. Every output pointer is validated before work;
results own their allocations. Deep-free summaries/pages with their matching
free functions; free the handle only without active calls, before its client.
`ChatSelectionClosed`, `ChatSelectionStale` and `ChatSelectionInvalidPage` append
statuses96,97 and98 without renumbering existing statuses. Ship the generated
header, Swift/Kotlin source and matching native library together.

The fixed-view entry point remains unchanged. `capture_chat_folder_selection`
adds existing flat and bounded smart-folder expressions. Relative-time predicates,
per-action eligibility aggregation and filtered live windows remain open.

### Complete existing-folder selection

`ChatFolderSelectionRule.version` must be1. Member IDs (maximum256) are exactly
32-byte account identities represented as hexadecimal; include/exclude group IDs
(maximum1024 each) are variable-length nonempty even hexadecimal strings up to512
characters. Uppercase IDs normalize to lowercase. The keyword is at most1024 UTF-8
bytes, trimmed once; empty or whitespace-only means absent. Excessive/malformed
inputs and unsupported versions return `ChatSelectionInvalidFilter` (C status99).

The member-any and keyword criteria combine with OR. Unread-only, unread-mentions,
groups-only, direct-chats-only, pinned-only, archive-side and effective mute
constraints combine with AND. Explicit `include_all` enables all eligible chats
on the selected archive side. With no member or keyword criteria, categories can
stand alone; contradictory group/direct categories match nothing. An otherwise
empty automatic rule matches nothing. Manual includes bypass automatic criteria,
including archive/mute, but cannot resurrect missing, blocked or departed chats.
Manual exclusions win over both automatic and manual inclusion. Ordering reuses
native pin/activity keys, and rules are frozen in the handle: recapture after an edit.

Keywords match the MDK-selected literal title and description using Unicode default
whole-string lowercase and literal substring containment. There is no regex, SQL
wildcard, accent or compatibility folding. Localized fallback labels are not literal
metadata. Display strings remain unchanged. Roster matching uses a separate complete
current-roster index, not the two-person peer-presentation table. Engine writes,
raw restores/imports and deletes invalidate or atomically replace those inputs;
upgrade/backfill runs in batches of50 without network or message-history access.
Migration107 also creates partial pending-send indexes, which requires a one-time
scan of existing timeline/submission rows during the transactional upgrade. Later
pending-send matching uses those indexes, not a message-history traversal.

If present, `smart_filter_json` replaces flat automatic criteria, preserving
manual inclusion/exclusion. This private JSON envelope has `version:1` and a
`root` group with `kind:"group"`, `all` (AND when true, OR otherwise), `not`,
and `children`. Conditions have `kind:"condition"`, uppercase `field` and `mode`,
`values` and `not`. Nested groups and conditions support negation. An empty root
is manual-only, including a negated root; nested empty groups are invalid.

Supported fields are `UNREAD`, `MENTIONS`, `DRAFT`, `PENDING_SEND`, `MUTED`,
`ARCHIVED`, `ACCEPTED` and `PINNED` (`PRESENT`/`NONE`, no values);
`PARTICIPANTS` (`ANY_OF`/`ALL_OF`/`EXCLUDES`, nonempty lowercase64-hex identities);
`TYPE` (`DIRECT`/`GROUP`, no values); and `TITLE` (`CONTAINS`, one nonblank literal).
Smart expressions may cross archive sides; use an `ARCHIVED` condition when needed.
The complete current native outbox, including older pending timeline sends, drives
`PENDING_SEND`; a received latest-message preview does not imply no pending sends.
Drafts include nonblank text or attachments. Deleted, invalidated or confirmed
timeline sends do not count as pending.

Limits are65536 UTF-8 envelope bytes, depth4 (root depth0),64 total nodes,64
unique values per condition, and256 UTF-16 units per title literal. Unknown fields,
unsupported combinations, malformed versions or any invalid subtree reject the
whole rule. A required source remains unknown under negation: incomplete roster,
type or selected-title evidence returns not-ready, never a partially authorized set.
User text is bound as SQL parameters. Smart title literals are not trimmed before
matching; flat keywords retain their legacy trim behavior.

Capture fails with `ChatPresentationNotReady` when required roster/classification/text
evidence is unknown or stale. Keyword capture and revalidation also fence shared
profile catch-up before and after the account query. No partially complete selection
is published. Counts/pages are frozen intent; revalidation only removes ids that
no longer match, supersedes old pages and does not authorize any mutation. Every
bulk command must still validate current command-specific permissions.

## Existing row gestures

`actions` is local display availability for existing client gestures. It is not
command authorization. Commands continue checking authoritative current state.

- `can_mark_read` / `can_mark_unread`: the effective unread toggle for accepted,
  active conversations. Pending invitations and departing/departed groups expose neither.
- `can_pin` / `can_unpin`: pin an unarchived row, or remove an existing pin.
- `can_mute` / `can_unmute`: the local preference toggle, including effective mute
  expiry. Archived/retained rows remain eligible (Android exposes these controls);
  clients may hide them as a layout choice. Neither mute nor pin joins a group.
- `can_archive` / `can_restore`: the explicit archive toggle, including retained
  departed history. Restoring archive state does not rejoin a group or move a departed
  group out of Left. Rejoining is a separate authoritative operation.
- `can_start_leave`: offer the existing leave flow for locally active, accepted membership.
  **Run authoritative leave preflight** before acting: an admin may need demotion,
  another admin, or a disband decision. This flag never promises `leave_group` will
  succeed and does not load the engine to make that promise. The row only knows
  projected lifecycle and membership: preflight can additionally reject unknown
  engine membership or an engine-only unrecoverable flag that is not yet reflected
  in the lifecycle projection. Admin demotion requirements also remain in preflight.
- `can_delete_local`: offer local deletion for terminal disbanded/left/removed
  history, with neither an unresolved leave request nor disbanding in progress.
  Confirmation UI remains client-owned. Queued departure exposes neither leave nor delete.

These hints do not dictate menu order, bulk-selection policy, confirmation text or
row layout. Selection, folder assignment and pin reordering continue using the
existing folder/pin APIs; they are host-specific menus rather than membership
authority. Android’s combined delete/leave flow must distinguish starting leave
from immediately deleting retained local history. These hints do not add accept/decline, disband or rejoin commands to list gestures.
Existing lower-level row and management APIs remain supported.

## Delivery and adoption checks

`row.last_message.delivery_state == Delivered` means local source-backed publication
state, **not** recipient delivery or a read receipt. Existing discriminants and
transport semantics are unchanged; richer delivery diagnostics remain separate work.

Before replacing client-side selection, verify text/attachment-only drafts,
empty/whitespace/reply-only drafts, incoming messages while a draft is selected,
clear/failure/newer-edit races, invite indicators, mute expiry, archived/Left gestures,
offline reopen, paging/anchor retention and live changes on both clients. Keep the
C9 device performance/adoption record separate from host binding round trips.
