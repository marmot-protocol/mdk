# Account attachment history

Use `account_attachment_history_page` to browse locally known attachments across one identity, without visiting each conversation. The existing `attachment_history_page` remains useful for a single conversation and preserves its canonical conversation order. Neither read starts acquisition, joins a relay, loads a message body, or decrypts files.

## Paging and filtering

`AccountAttachmentQueryFfi` has group and sender selections plus inclusive `after`/`before` timeline timestamps. Empty selections mean all. Selections use OR within each list and AND across lists and dates. IDs are case-normalized, sorted and deduplicated before cursor binding; groups are nonempty opaque MLS IDs, not 32-byte Nostr routing IDs. Group IDs are capped at 256 bytes and senders are 32-byte hexadecimal keys. Each list has at most 100 input entries. Invalid IDs, reversed/overflowing dates and limits outside 1–100 return typed outcomes without rows.

Each page seeks at most `limit` original attachment candidates plus one look-ahead slot in the existing SQLite attachment index. It returns group/source/message identity and the typed shared-parser attachment outcome, including rejected slots and original album indices. Ordering is newest timeline time first, then group/message identity, then original album order. No message-level page is split by a host.

Group/sender filtering applies within that bounded candidate page. A page can be empty while `has_more` is true. Continue from its `next_cursor`; empty entries are not exhaustion. Hosts may consume a small bounded number of pages for a visible batch, but must return the last consumed continuation rather than search until a page fills. Category/role filtering can similarly use the typed outcomes within a bounded batch. This primitive is not the fixed-view text-message search session or a filename-search API.

Opaque cursors bind the account store incarnation, canonical query and global attachment-source revision. Changes to existing attachments, visibility, source metadata, album order or emoji roles conservatively return `RestartRequired`. Additions advertise a separate head refresh and preserve existing seek cursors. Reactions and non-attachment arrivals are quiet. Discard all loaded rows before reading from the head; never append a refreshed first page to old pages. `account_attachment_history_version` gives a constant-work change token even after exhaustion. Keep the original loaded-page baseline and compare using `change_since`.

Expiry is checked on each read, even before retention maintenance erases the source. A page includes `next_expiry`, a conservative earliest account retention deadline. While the screen is visible, schedule one invalidation at that deadline and compare a fresh version before displaying retained rows; do not infer validity from an unchanged database revision alone. Retention-policy changes and elapsed expiry invalidate old cursors. Cancel the one-shot UI task on navigation/background and reread on resume.

Retain handles in memory only and discard them after runtime reconstruction. Account switches cancel screen work, close native handles and clear prior rows. Closing an observer or cursor does not cancel acquisition. Use existing runtime/presentation invalidation events to refresh; no diagnostic polling loop is required.

## Bounds and privacy

The account page uses an indexed seek, not a per-chat fan-out or an account-wide filtered scan. At most 101 slots are visited per read and only bounded result metadata crosses the API. Slot and emoji metadata each have a 32 KiB bound; a page has a 512 KiB metadata budget. Oversized metadata returns `ResponseTooLarge` with no partial page. This is a typed read failure, not an empty library or permission to download the source.

The query, entries and opaque native handles have redacted Debug implementations. Do not log identifiers, filenames, URLs, query text or parser payloads. Source visibility is maintained by the existing block/invite/deletion/invalidation and retention machinery; the account cursor is invalidated by its shared revision triggers. Looking up an attachment does not grant permission to download it.

## Opening and ownership

Use the complete account/group/message/source/index identity to revalidate the selected attachment through existing native local access and transfer APIs. Download only after explicit intent or existing automatic policy permits it. Account pages do not copy retained bytes or create a second protocol cache. Source removal or a changed identity must produce an unavailable result rather than opening a previous file.

Swift/Kotlin own returned native objects and close/drop them with the screen/session. C owns the root page result and deep-frees it once; cursor/version fields are borrowed while that root is live. Clone a version baseline before freeing its page if it must survive for later comparison. Calls use the matching generated bindings/header and native library; source support does not establish a published SDK or validated client adoption.
