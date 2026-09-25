# Native conversation window

C5 M5 exposes one prepared conversation through Swift/Kotlin and C. This is an
additive API: existing timeline, group, message and draft queries remain available.
Publishing a MarmotKit release, migrating apps and measuring devices remain C9.

## Open and render

Call `open_conversation_window(account, group, mode, message_id, initial_rows,
timeout_ms)`. The group is an opaque MLS id (including current 16-byte ids).
`Automatic` opens first unread for accepted conversations, otherwise latest.
`Latest` follows the tail; `Message` requires an explicit retained message id.
Rows default to 50 and accept 1–200. No opening or paging action marks messages read.

Take `snapshot()` once, then drive one `next()` receive loop. Each result replaces
the complete retained window. Render `header.selected` directly, localize its
structured text, and index `identities` by `account_id_hex`. Every identity reference
in `messages[*].references` is resolved there or explicitly absent. These are
window-scoped display identities, not a roster or a source of mutation authority.

The first snapshot reads the durable account projection directly, without waiting
for worker startup, group hydration or relay catch-up. Render its messages immediately.
`header.epoch == None` means live authority is not yet available: membership and
invitation/departure display come from that same local read, all send/management
capabilities are false, and non-disbanded lifecycle is conservatively `Recovering`.
Do not show an MLS recovery warning solely from that local-only lifecycle value.
Do not interpret this as removal, wait for `can_send` to display history, or restore
an independent client timeline cache. MDK retries authority in the background and
publishes a complete replacement with an epoch and current capabilities when ready.
That upgrade commonly supersedes the initial revision immediately: install it before
issuing revisioned commands, or handle `StaleWindow` by consuming the latest replacement.
Before the first live capture, paging and local updates remain available during
catch-up: captures have a 50 ms wait budget before falling back to fresh local data.
After live authority arrives, queued captures await the worker without that display
timeout, retaining the last complete snapshot. During an outgoing send, the worker
captures registered open windows for the sending group after the local pending
projection and before awaiting transport, then again after settlement if
notification publication introduces another transport wait. Retraction and sends
with no remaining transport wait use the normal invalidated worker read. These reads use
the same live authority/account boundary as normal captures, so pending rows can
reach the open screen while publication is stalled. Checkpoints coalesce per
window, respect its current viewport, and are discarded when that viewport changes.
Every consumed checkpoint schedules a fresh worker read, so invalidations newer
than the checkpoint cannot be lost when the window drains queued signals.
They never downgrade the composer or combine stale permissions with newer local
rows. An explicit `NotReady` response
from the worker still schedules a quiet retry. Worker acquisition runs to completion
outside the capture timeout and retries transient failures; closing the window never
abandons worker teardown. A missing/dirty local read projection uses the existing
keyed preparation/retry path.

Timeline content uses the existing Markdown/media converters. For this screen,
raw tags, full reactor lists and raw `media_json` are omitted from the compatibility timeline record;
use the bounded `references.reactions` tallies/previews and truncation flags.
System presentation is exposed only for stored authenticated system rows. Media
outcomes preserve rejected attachments in order. Bytes remain separate local/media
operations; the screen never downloads them. Low-level timeline queries still
provide their original raw fields and collections, including raw media JSON when
a caller needs to inspect a rejected attachment beyond its typed rejection outcome.

Each displayed `references.reactions.items` entry includes `viewer_reacted`
(Swift/Kotlin `viewerReacted`). Use this flag to highlight the viewing account's
active reaction for that emoji. It uses the complete active reactor list, not the
bounded two-identity preview, and refreshes with live reaction additions/removals.
No separate timeline query or viewer identity lookup is needed for these chips.
The existing reaction-kind cap and `omitted_kinds` still apply; this flag does not
expose reactions for omitted emoji kinds. The compatibility timeline's raw
`reactions` remains empty; expanded reaction details still use the narrow APIs.

Regenerate native sources and use matching libraries when adopting this field:
it changes the UniFFI record schema and the C `MarmotConversationReaction` layout.

## Paging and lifetime

Commands can run while `next()` waits. Supply the revision from the installed
replacement; install the command result and deduplicate its stream echo by
`generation`/`sequence`. Commands apply to the current retained viewport: a
revision stays valid across background replacements (new rows, delivery state,
reactions, header, draft) and goes stale only once a replacement showing a
command's viewport move is published.
A stale sequence means refresh/reassess before retrying.
A foreign generation is a distinct error: discard that revision and use the
current handle's snapshot.

Report the actually visible message using `set_visible_anchor` before paging
beyond the retained 200-row context. Paging preserves that anchor, so a saturated
page can return unchanged rows while stored-history flags remain true. Keep pixel
offsets on the client. `return_to_latest` resumes following arrivals and retains
the current row budget. Explicit jumps to missing targets return
`ConversationWindowMessageNotRetained` (C status `MARMOT_STATUS_CONVERSATION_WINDOW_MESSAGE_NOT_RETAINED`).
Keep the existing window and viewport on this error; further commands and updates
remain available. Other `ConversationWindowQuery` errors are terminal and require
reopening. Opening on a missing explicit target returns the same missing-message
error without creating a handle.

`ConversationWindowNotReady` (C `MARMOT_STATUS_CONVERSATION_WINDOW_NOT_READY`)
is retryable, not a terminal query error. Keep the installed window and keep
receiving: MDK repairs dirty read state and retries accepted work in the background.
Reassess a failed command after the next successful replacement instead of opening
another handle or immediately repeating it. Opening retries only if its durable
local projection is not yet readable, until it succeeds, is cancelled, or reaches
its deadline. Unavailable live authority does not delay the initial local snapshot.
`ConversationWindowAnchorOutside` (C `MARMOT_STATUS_CONVERSATION_WINDOW_ANCHOR_OUTSIDE`)
rejects an anchor outside the current retained rows without closing or changing the
window. Use the latest installed replacement and report an actually visible retained
row with its revision; use an explicit jump if navigation outside that window is intended.

Opening and each window command take a deadline: zero selects **30 seconds**,
otherwise milliseconds. Cancelling/timing out opening abandons it. A command that
was already accepted may complete after its waiter times out or is cancelled;
consume the stream and refresh before retrying. `next()` is cancellable without
consuming a pending update. C `next` uses its existing timeout convention: zero
waits indefinitely; a timeout returns `MARMOT_STATUS_TIMEOUT` with a NULL result.
Thus the same C value `timeout_ms = 0` means a 30-second deadline for open/page/anchor/
jump/latest commands, but unlimited waiting for `next`; it is not a universal
"disable deadlines" value.

Call and await `cancel()` to wake waiting operations and release the runtime
window. Then release/destroy the native object. Kotlin's generated `close()`/`use`
releases its native reference; `cancel()` is the explicit async cancellation API.
Runtime shutdown, account-store teardown and replacement of the pinned account
worker close the window. Reopen after terminal `Closed`/end-of-stream; ordinary
transport reconnect backoff remains retryable on the same handle.

C calls borrow all inputs. Free every returned snapshot with
`marmot_conversation_window_snapshot_free`; free the subscription before its client.
`marmot_conversation_window_subscription_cancel` can wake concurrent calls, but
never free a handle until those calls return. Output pointers are validated before
operations/dequeues and are NULL on failure. C supports blocking receive; there is
no callback adapter for this fallible replacement stream.

## Drafts

The selected draft contains descriptors plus an opaque revision object. Keep that
revision for `save_message_draft_if_revision`, `clear_message_draft_if_revision`,
`message_draft_attachment_if_revision` and `send_message_draft`. Revision conflicts
have a distinct error. C revision pointers are borrowed from the owning snapshot
or selected-draft result; retain that owner while calling these methods.
Call `marmot_selected_message_draft_free` only for a directly returned selected-draft
root pointer. Never pass `&snapshot->draft`: that inline field and its children are
released by `marmot_conversation_window_snapshot_free`.

Use `send_message_draft` with the prepared attachment references matching the
selected descriptors. MDK clears only that revision on durable acceptance; never
independently delete it when delivery finishes. Later edits and failed acceptance
remain intact. The local attachment accessor distinguishes missing bytes from an
empty attachment and refuses stale revisions.

## Validation and limits

For an existing chat screen, replace its separately assembled opening state with
the initial window snapshot, then replace that state from the receive loop. Route
paging and jump actions through the same handle. Serialize installation on the
UI owner and ignore an equal or older sequence within its generation: a command
result and its stream echo can arrive in either order. On reopening, retire the
old handle and reject its late results even if their sequence is larger.

The compile-checked [Swift](tests/chat_projections_smoke.swift) and
[Kotlin](tests/chat_projections_smoke.kt) `compileConversationCommands` examples
show the generated method names and argument shapes. They illustrate individual
calls, not a complete UI receive loop. Keep existing explicit read acknowledgements,
full-roster management and media preparation/local-byte access alongside this handle.

Rust boundary tests exercise actual local-relay account workers, independent
receive/page operations, draft revisions, deadlines and cancellation. C tests
exercise output preflight, invalid discriminants, timeout, concurrent commands
and allocation-audited deep frees. `just uniffi-projections-smoke swift|kotlin`
regenerates host bindings, round-trips the new records and compiles the command
surface. These are host binding checks, not device or published-artifact evidence.

The window retains at most 200 rows and uses M3's bounded identity/reaction sidecar.
UniFFI retains a subscription-local conversion cache for the current rows. Unchanged
rows reuse their converted values; unchanged text and kind reuse Markdown tokens
even when delivery, media, or other row metadata changes. Header, draft, identity,
read-state and bounded reaction references always come from the new snapshot.
Paging prunes departed rows, older command replies cannot roll back the cache,
and cancellation releases it. Raw tags and full reactor lists do not enter it.
The cache retains normalized source rows and converted rows, including two additional
copies of each row's plaintext alongside the runtime snapshot, for up to 200 rows
per subscription. Departed rows are released on replacement; cancellation clears all rows.
This reuse is justified by host conversion benchmarks so far; it does not complete
C9's device measurement gate or establish a device latency improvement.
The public API still delivers complete replacements: cloning, serialization and
native UI reconciliation remain proportional to the returned content. C9 must
measure end-to-end device latency at 50 and 200 rows, including long Markdown;
see #1838. The binding layer owns an initial converted snapshot and the runtime
subscription; do not open duplicate handles for one screen. No new durable
projection or media cache is introduced.

## Accepted edits (C6a)

Timeline `plaintext` and Markdown tokens now carry the accepted effective text; reply and selected chat-list
previews use the same durable projection. `edit` contains the accepted edit count, latest edit id and edit timestamp.
Render that metadata directly; do not overlay raw edit events again. Ordering, delivery, media and message identity
stay attached to the original message. Unread and mention eligibility use its original content.

`message_edit_history` / `messageEditHistory` returns 1–100 accepted replacement versions, oldest first within a
latest-first page. Pass the first entry's timestamp and id as the exclusive cursor for older versions. C uses
`marmot_message_edit_history` and `marmot_timeline_edit_history_page_free`. This synchronous details query should run
off the UI thread. It resolves retained edits scoped to the requested target, then bounds the returned page; it is
not a constant-work history query. Normal screen reads use persisted compact metadata, not that history resolver.

The same account author and exactly one `e` target are required. Invalidated and self-retracted edits are excluded;
latest inner timestamp wins, with lexicographically greatest event id breaking ties. Removing/invalidation of a
winning edit falls back to the next accepted version, or original content. Deleted/invalidated/hidden targets expose
no accepted history. Raw kind-1009 events remain available through `messages`, but no longer appear as standalone
materialized timeline rows. This is a deliberate timeline behavior change; regenerate bindings and update clients
together. `LastMessageContentChanged` is a non-activity chat-list trigger. Migration 76 repairs persisted targets and
previews without replaying relays. C6b system preview semantics and C7/C8 asset acquisition remain separate.
