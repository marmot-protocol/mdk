# Attachment history native handoff (C8-B)

Use `attachment_history_page(account_ref, group_id_hex, limit, cursor)` for a
conversation's full attachment library. It reads the local canonical index without
opening an engine, warming secrets, contacting relays, or starting downloads.
Swift/Kotlin calls are async; C equivalents block and belong off the UI thread.
Group IDs are opaque MLS IDs, including 16-byte IDs, rather than 32-byte route IDs.

## Paging and categories

1. Start with no cursor and a limit from 1 through 100. The limit counts original
   slots, including rejected attachments. Each entry includes source/message IDs,
   sender, display/received timestamps, optional source epoch, MDK category and the
   shared parser's accepted reference or typed rejection with its original index.
   Discovery honors the runtime's explicit loopback-development flag. The existing
   timeline/chat-list classification paths use strict public-endpoint policy;
   loopback fixtures can therefore have different verdicts across those surfaces.
   Production configurations keep loopback disabled.
2. Preserve MDK's canonical order and use `(message_id_hex, attachment_index)` as
   the item identity. Do not sort by display timestamps or renumber rejected slots.
3. `has_more` means `next_cursor` is present. Filter each page by category if needed;
   zero matches with `has_more` still true means the selected tab is partially
   loaded, not empty. Load further pages in bounded, cancellable UI work rather
   than draining the entire history before showing results. Audio is not proof of
   voice-note intent. URL-only links are not part of this API.
4. `InvalidLimit` and `CursorMismatch` are typed results. Correct the request;
   cursors are scoped to the account database and group that issued them.

Legacy rows retain `source_epoch = None`; the reference's compatibility fallback
of zero is not evidence that epoch zero was stored. Discovery is not assurance of
local bytes, permission to fetch, or availability of an epoch secret. Existing
`download_media` still enforces fetch policy. Automatic attachment acquisition
remains deferred until invitation acceptance and is not implemented by C8-B.

## Refresh, removal and restart

Keep the version captured when the current loaded collection began as its baseline.
Use `attachment_history_version` on screen resume and after relevant projection
updates, including after exhaustion or an empty initial result. Compare current
with baseline using `change_since`:

- `Unchanged`: retain loaded rows.
- `Additions`: current cursors remain usable. New rows below the cursor can appear
  during later paging; additions above a passed boundary need a separate refresh.
  Keep the baseline until the collection is actually refreshed so deferred additions
  remain detectable. This is a changing collection, not a fixed snapshot.
- `RestartRequired`: discard loaded rows and cursors, then fetch the head and adopt
  its new baseline. Deletion, invalidation, replacement/reordering, blocking and
  group generation changes take this path. A page request can also return this
  outcome. Never append a fresh first page onto a stale collection.

Discard late responses from obsolete account/group/screen requests. When a refresh
requires replacement, do not keep displaying deleted rows while loading that
replacement. Version reads are local snapshots, not a promise that nothing changes
immediately afterwards. No additional long-lived subscription is needed by this
slice; hosts reuse projection wakeups/resume and the authoritative version probe.

Handles are opaque, process-local and contain no database ownership. Do not persist
or reconstruct them. On runtime reconstruction start from the head; discard handles
at account removal/reset. All reads fail after terminal `shutdown_and_close`.

## C ownership

`marmot_attachment_history_page` returns a `MarmotAttachmentPageRead`. A successful
page owns entries, version and optional cursor. Borrow those handles only while the
owning result is alive; the next result is independent. Free the result once with
`marmot_attachment_page_read_free`; never free its fields separately. Use
`marmot_attachment_history_version_clone` to retain the page's exact baseline as
an independently owned handle before freeing the page. Free that clone with
`marmot_attachment_history_version_free`. Do not replace it with a later version
read: that could conceal a deletion between the page and version reads.

`marmot_attachment_history_version` returns a standalone version, freed with
`marmot_attachment_history_version_free`. Compare it against the borrowed baseline
with `marmot_attachment_history_version_change_since`. Required out-pointers are
validated/cleared before work. Regenerate sources/headers and pair them with the
matching library; this is not evidence of released-artifact or device adoption.
