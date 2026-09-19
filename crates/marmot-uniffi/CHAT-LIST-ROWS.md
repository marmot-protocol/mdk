# Complete chat-list row previews and actions

This is the **unreleased C3 follow-up to MDK 0.10.2**. It adds fields to
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
- `can_start_leave`: offer the existing leave flow for locally active membership.
  **Run authoritative leave preflight** before acting: an admin may need demotion,
  another admin, or a disband decision. This flag never promises `leave_group` will
  succeed and does not load the engine to make that promise.
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
