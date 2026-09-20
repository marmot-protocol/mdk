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
