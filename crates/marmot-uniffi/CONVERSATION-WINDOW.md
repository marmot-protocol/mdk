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
`generation`/`sequence`. A stale sequence means refresh/reassess before retrying.
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
another handle or immediately repeating it. Opening itself waits through this state
until it succeeds, is cancelled, or reaches its deadline.
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
Conversion is local and proportional to returned content **on every replacement**:
all retained chat rows are converted and their Markdown is parsed again, even if
only one message or a header/draft field changed. At the 200-row cap this is
full-window work per update. C9 must measure native conversion wall time per
replacement during message bursts at 50 and 200 rows, including long Markdown;
see #1838. No incremental-conversion or device-latency guarantee is implied. The binding layer owns
an initial converted snapshot and the runtime subscription; do not open duplicate
handles for one screen. No new durable projection or media cache is introduced.
