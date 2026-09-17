# Group content reports and admin deletion

The canonical wire contract lives in Marmot's
[`features/content-moderation.md`](https://github.com/marmot-protocol/marmot/blob/master/features/content-moderation.md).
The companion specification was merged in Marmot PR #423.

Reports are unsigned inner kind 1984 events encrypted through the ordinary group
transport. `report_message` resolves the target author and sends a NIP-56 category
and optional explanation. Each report event is independent. MDK does not merge
reports by reporter, require a revision tag, or impose group-size/name eligibility.

Admins use `dismiss_reports` to attach a kind-1985 NIP-32 `dismissed` label to
specific report IDs, with an optional explanation. Labels do not hide the target,
resolve other reports, or select a winning administrator. `content_reports` pages
individual reports for a group or message; `report_dismissals` pages the labels
on a particular report. A report's `dismissed` flag means at least one currently
valid source-authorized dismissal label references that event.

The existing `delete_message` API sends kind 4891 when an active admin deletes a
whole chat message, including an unreported message or their own message. This
hides its original content, edits, and attachments in message projections. Other
authors still retract their own content with kind 5. Kind 4891 does not extend
NIP-09, and a dismissal cannot undo a deletion. Admin deletion intentionally uses
one moderation operation for all whole-chat targets, regardless of authorship.
This includes self-deletion: older peers may keep that content visible, and a
demotion before encryption rejects the operation rather than changing it to an
author retraction.

Timeline records expose `has_reports`. Existing timeline and projection events
carry updates; there is no dedicated shared review queue, pending count, or
message moderation status. Clients choose their grouping, counters, review UI,
and notification policy. MDK does not insert control events as chat rows or add
unread activity. `reported_message` returns the current deletion-masked projection
for a reported target even when personal blocking hides its normal timeline row.
This lookup is available to all members, including non-admins; hosts choose whether
to expose it outside admin review.
Neither report records nor labels contain a stored copy of target content.

Admin authorization is derived from authenticated source-group state. Demotion
later does not invalidate that authority; convergence withdrawal of the event
withdraws its effects. Unknown authority remains unresolved and retryable. These
requirements apply to dismissals and admin deletions, not to member reports.

Reports and labels follow ordinary retention. Deleting or expiring a target does
not erase a report explanation that quotes it. Expired deletion controls retain
minimal evidence to prevent deleted content from returning. Suppression retains
unexpired underlying content so convergence can withdraw an invalidated action;
there is no user-facing undo or restoration operation.

Compatible clients are needed for consistent enforcement. Older clients may
render unknown events or retain earlier deletion behavior. Existing honored
legacy kind-5 tombstones remain honored locally, while newly received kind-5
events are author-only.

Message presentation exposes typed `deletion_source` on timeline/conversation rows,
chat-list previews, reply previews, and `reported_message`. It describes the selected
accepted deletion: author-authorized kind 5 is `Author`; authenticated kind 4891 is
`Admin`, including self-removal. Legacy kind-5 removals of another author's content
remain honored but are `Unknown`, as are tombstones without recoverable evidence.
This does not infer an administrator from sender identity or present-day roles.
The greatest `(authenticated event timestamp, event ID)` selects both provenance
and the existing deletion ID. Withdrawing evidence updates the winner and live
projections; convergence invalidation remains a separate field.

Migration 0081 adds columns defaulting to `Unknown` without replaying history or
changing masking and deletion IDs. Normal reprojection can classify retained
accepted evidence. See the [bindings contract](../../../crates/marmot-uniffi/README.md#deletion-provenance-and-custom-events)
for client fallback wording and coordinated native/binding upgrade requirements.

See [implementation details](../further-context/content-moderation.md) for source
authority recovery, persistence, and bounded migration.
