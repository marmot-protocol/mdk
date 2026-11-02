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
remains deferred until invitation acceptance; use the
[attachment acquisition contract](ATTACHMENT-ACCESS.md) for demand and local reads.

## Reaction artwork

Use `reaction_attachment(account_ref, group_id_hex, reaction_message_id_hex)`
to resolve one custom reaction's artwork. Pass `reactionMessageIdHex` from the
conversation reaction or reaction details, not the message the reaction targets.
This bounded local read requires no account worker or relay connection and starts
no download. It returns one `AttachmentEntryFfi` only when the active reaction's
custom shortcode names a matching validated encrypted image attachment. An absent,
removed, invalidated, hidden, expired or unmatched source returns `None`; keep the
sanitized `:shortcode:` fallback. An `emoji` tag URL alone is not an attachment
and must never be fetched directly.

The reaction ID must be exactly 64 hexadecimal characters; malformed IDs return
`InvalidMediaReference`. The lookup considers only original `imeta` indices
0 through 99, with no continuation scan. Source tag JSON and each candidate slot
are limited to 16 KiB, and reaction content to 64 UTF-8 bytes including the
surrounding colons. Oversized metadata, artwork beyond those indices, or no
eligible match produces `None`; keep the shortcode fallback. The first
well-formed definition for the reaction's exact shortcode wins, even if its
locator matches no image; a later duplicate definition does not override it.

Build an `AttachmentLocalTargetFfi` from the returned `messageIdHex`,
`sourceMessageIdHex` and accepted attachment's original `attachmentIndex`. Use
`attachmentLocalAssets` and `readAttachmentAsset` for verified local bytes. When
they are absent, submit `requestAutomaticAttachment` under the account's existing
host-managed permissions, observe the ordinary transfer state, then read the local
asset. An explicit user download uses `requestExplicitAttachment`. Neither path
needs `listMedia` or `downloadMedia`, and discovery itself grants no permission.

Scope requests and any in-memory image cache to the account, runtime incarnation,
chat and exact reaction source target. Different events using the same shortcode
can name different images. Re-resolve when the projected earliest active reaction
ID changes; discard late results for a prior ID. Retraction, deletion, invalidation,
blocking, expiry and local source removal revoke subsequent acquisition/local
reads. Opaque asset references do not authorize retaining an old image after its
reaction disappears. Replace it or show the shortcode fallback as authoritative
reaction state changes.

### Adoption and database upgrade

The reaction source migration is additive and backfills eligible retained reaction
events; no account reset or host-owned reaction database is needed. Pair generated
Swift/Kotlin bindings and C headers with their matching native library. Existing
reaction metadata and ordinary attachment APIs remain supported. The capability
is a source contract, not proof that a published MarmotKit artifact or downstream
app already includes it. On adoption, qualify a retained reaction across upgrade
and restart, a new peer reaction, repeated shortcodes with different artwork,
earliest-reaction replacement, deletion, permission denial and stale late results.

## Inline emoji artwork

Each entry carries `role` (`Shared` or `InlineEmoji`) separately from its MIME
category. Gallery clients exclude `InlineEmoji`; the API still returns every
original slot and its parser verdict, so an emoji-only page can have no gallery
items while `has_more` remains true. Never renumber slots or stop on a filtered page.

The native classifier matches accepted image locators exactly against well-formed
`["emoji", shortcode, locator]` tags, optionally with a fourth emoji-set address,
on that source message. The classifier ignores tags with more than four fields.
Shortcodes use 1–64
ASCII letters, digits, underscores or hyphens. The first well-formed definition of
a shortcode wins, even when its locator does not match an attachment. Aliases are
supported. Every image slot matching a claimed artwork locator has the inline role;
rejected slots and non-images retain `Shared`. This role does not authorize or
suppress acquisition, and does not depend on whether the shortcode occurs in text.

### Android adoption requirement

Android's current `Nip30Emoji.attachmentShortcodes` uses `firstOrNull` and marks
only the first matching image slot. Native history intentionally classifies every
accepted image slot with the claimed locator as `InlineEmoji`. Before adopting
this role in the gallery, update Android's conversation attachment classification
to the same all-matching rule. Otherwise a duplicate artwork slot could remain a
conversation photo while disappearing from the gallery. Preserve the first
well-formed definition per shortcode and the three-or-four-field tag policy,
original slot indices and acquisition
references in both surfaces. Qualify duplicate locators and aliases in the
consumer; the native regression `attachment_discovery_roles_preserve_slots_and_refresh`
already covers two matching slots and an alias.

Metadata is point-read from canonical source tags within the page's read snapshot,
including retained rows predating this capability; no history backfill is needed.
Source-tag changes invalidate versions/cursors. Bindings add `AttachmentRoleFfi`
and the entry's `role` field; C adds `MarmotAttachmentRole` and changes the entry
layout. Regenerate Swift/Kotlin bindings and pair the C header with its library.

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


## Swift and Kotlin handle ownership

Each page returns native object handles for its version and optional next cursor.
Kotlin hosts should explicitly `close()` handles when no longer needed and use
`use { ... }` for short-lived standalone version probes. Keep the initial page's
version open as the collection baseline; assigning it to another variable aliases
the same object and does not make it safe to close through the page reference.
Close later page versions after processing, and consumed cursors after their
paging call completes, unless still needed by another in-flight operation. Close
the baseline and any remaining cursor when replacing or discarding the collection.
Swift releases these objects through ARC; drop unneeded references at the same
lifecycle boundaries. Do not accumulate every page's handles until screen teardown.

## C ownership

`marmot_reaction_attachment` blocks off the UI thread and writes an owned
`MarmotAttachmentEntry`, or NULL with `MARMOT_STATUS_OK` when unavailable. Free
this standalone result with `marmot_attachment_entry_free`. Entries borrowed
from a page belong to that page and must not be freed separately.

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
