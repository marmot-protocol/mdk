# Group content reports and review

The wire contract belongs to Marmot's `foundation/application-messages.md` and
`features/content-moderation.md`. Merge that companion specification before
shipping this implementation. All participants need compatible clients for a
consistent moderation view; older clients can render unknown kinds or retain
older deletion authorization behavior.

## Runtime boundary

`report_message` resolves the original author from account storage and validates
the requested original/edit revision. A report targets a whole kind-9 message,
including media and completed agent messages. Named two-member groups remain
eligible. `dismiss_reports` accepts explicit report IDs and requires admin
preflight. Reports use inner kind 1984. Dismissals use NIP-32 kind 1985 with the
`dismissed` label in namespace `marmot.report-review.v1`, referencing report IDs.
The existing delete command sends kind 5 for author self-retraction and kind 4891
for admin removal of another member's whole chat message. Kind 4891 references
the original message and carries `{"v":1,"action":"remove"}`. This does not
extend NIP-09 authorization.

The runtime, UniFFI, and C surfaces expose bounded `reported_content` and
`message_reports` pages, report/revision metadata, moderation summaries, and a
`subscribe_reported_content` snapshot plus live updates. Review details include
the current message and the reported revision, with normal attachment decoding.
These queries bypass personal timeline blocking. App gestures, badges and
review screens belong to clients.

Report and review controls never create timeline rows, unread increments, or
push notifications. Queue subscribers refresh on the group's committed
projection updates, including after broadcast overflow. Queue and detail cursors
are exclusive message/report IDs; page sizes are clamped to 1–100.

## Authenticated authority

The engine derives `AppMessageAuthority` from the MLS state used at encryption
or authenticated receive. It binds the verdict to a SHA-256 digest of that
state's epoch authenticator, and records group eligibility and admin authority.
This evidence is local metadata, never an author-supplied event claim.

The verdict travels through the session publish work, durable outbound fanout,
account publication result, replay observation, durable pending application
output, and app projection. A queued intent receives its verdict when it is
actually encrypted. Receive-time current admin lists do not authorize an action.

For a historical receive, the engine restores the retained source snapshot
under a rollback guard and authenticates the ciphertext and payload there before
reading its policy. An equal epoch number on a different branch is insufficient.
The guard restores live ratchets and group state even on failure. Missing proof
leaves the authority unresolved. A separate durable retry record retains the source ID, sender, epoch and payload
digest without plaintext. Application outputs can therefore be acknowledged and
explanations pruned while bounded, rotating recovery batches remain retryable.
A recovered verdict and its dependent projections commit atomically. Source
verdicts survive restart, while convergence invalidation still withdraws effects.
Historical pre-migration deletion decisions remain frozen, including already
honored admin kind-5 tombstones. New source-authorized kind-5 events cannot gain
admin deletion privileges.

## Persistence and retention

Migration 0077 adds source-authority metadata, indexed report and moderation
projections, and a durable backfill cursor over the pre-migration event prefix.
Maintenance advances at most 100 old events per batch. Normal receive reprojects
only affected message targets via modifier edges.

Reports are grouped by original message, revision, and reporter within one
group. The earliest `(created_at, event_id)` chooses displayed duplicate details.
A dismissal referencing any duplicate resolves that logical report. Concurrent
valid dismissals choose the same canonical decision; a later report from a new
reporter/revision remains pending. Removal wins over edits and review status.

Report records contain references and metadata, never a copy of target content.
Expiration of the target prunes dependent explanations and edits. Expired
controls retain structural evidence with explanations scrubbed so duplicate
reports, rebuilds, or late edits cannot resurrect dismissed or removed content.
Normal timeline, reply-preview, search, media, and review-detail content is
suppressed after removal. There is no withdrawal, undo, or restore operation.

The event write, modifier edges, per-message summary, logical reports, and queue
counts use the account database transaction rail. Publication failure follows
the existing local projection invalidation and retry behavior.
