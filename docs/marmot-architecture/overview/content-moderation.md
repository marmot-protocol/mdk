# Group content reports and review

The wire contract belongs to Marmot's `foundation/application-messages.md` and
`features/content-moderation.md`. Merge that companion specification before
shipping this implementation. All participants need compatible clients for a
consistent moderation view; older clients may render unknown kinds, retain
removed content, or retain older deletion authorization behavior. Compatibility
runs both ways: older clients ignore kind-4891 removal, while upgraded clients
reject newly received cross-author admin kind-5 requests. Only previously honored
legacy tombstones remain frozen; no receive-time admin fallback is introduced.

## Runtime boundary

`report_message` resolves the original author from account storage and validates
the requested original/edit revision. A report targets a whole kind-9 message,
including media and completed agent messages. Eligibility counts distinct
member accounts, so multiple devices do not turn an unnamed two-account chat
into a moderatable group. Named two-account groups remain eligible. The shared
`reporting::group_reporting_allowed` helper pins the protocol's Unicode whitespace
set for app preflight and engine authorization; an absent profile name is empty
for this check. `dismiss_reports` accepts explicit report IDs and requires active
admin preflight. Reports use inner kind 1984. Dismissals use NIP-32 kind 1985 with the
`dismissed` label in namespace `marmot.report-review.v1`, referencing report IDs.
`delete_message` sends kind 5 for author self-retraction and kind 4891 for active
admin removal of another account's whole chat message and all its revisions.
A non-admin targeting another account's message receives an error before
publication. Kind 4891 references
the original message and carries `{"v":1,"action":"remove"}`. This does not
extend NIP-09 authorization.

An author retraction hides the content without resolving its reports. Only an
effective kind-4891 control gives `ModerationStatus::Removed` and removal
attribution; kind-5 tombstones keep pending/reviewed report state independent of
content availability. Later reports can reopen a retracted message's review.
Convergence withdrawal of a kind-4891 control reopens unresolved reports even
when an author tombstone still hides the body.

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

The branch digest is retained with moderation verdicts as provenance of the
policy decision, including when the original source snapshot has been pruned.
It is not an admin credential or an alternate branch-selection input. Ordinary
chat, reaction, edit, and author-deletion events omit this evidence; only the
three moderation kinds pay for its member/policy lookup and persistence.

The verdict travels through the session publish work, durable outbound fanout,
account publication result, replay observation, durable pending application
output, and app projection. A queued intent receives its verdict when it is
actually encrypted. Receive-time current admin lists do not authorize an action.

Historical source authorization restores the retained source snapshot under a
rollback guard and authenticates the ciphertext and payload there before reading
its policy. An equal epoch number on a different branch is insufficient. The
guard restores live ratchets and group state even on failure. Out-of-epoch replay
emits unresolved authority instead of nesting another rewind inside replay.

A successful source probe supplies both authority and retention. If its
authentication fails, ingestion keeps the existing source-epoch retention
fallback used by ordinary messages, while authority remains unresolved. Failure
to prove moderation authority must not exempt report explanations from expiry.

A separate durable retry record retains the source ID, sender, epoch and payload
digest without plaintext. Only kinds 1984, 1985, and 4891 enter this path;
ordinary messages and kind-5 author deletion do not. Session/account
`run_due_maintenance` drives `recover_pending_application_authority` in rotating
batches of at most 32 pending records, independently of legacy projection
backfill. Unknown authority stays retryable rather than becoming a denial.

A memory-only attempt cache keys each source message ID to its named snapshot's
content fingerprint. Repeated attempts that could not authenticate skip the
rewind until those snapshot bytes change. Resolving authority clears its entry;
each full cursor pass reclaims entries for retry requests that disappeared.
Pruning retained source bytes removes their retry requests atomically.

Application outputs can be acknowledged and explanations pruned while recovery
remains pending. A recovered verdict and its dependent projections commit
atomically. Source verdicts survive restart, while convergence invalidation
still withdraws effects. Historical pre-migration deletion decisions remain
frozen, including already honored admin kind-5 tombstones. New kind-5 events
cannot gain admin deletion privileges.

## Persistence and retention

Migration 0077 adds source-authority metadata, indexed report and moderation
projections, and a durable backfill cursor over the pre-migration event prefix.
Maintenance advances at most 100 old events per batch. Normal receive reprojects
only affected message targets via modifier edges.

Reports are grouped by original message, revision, and reporter within one
group. The earliest `(created_at, event_id)` chooses displayed duplicate details.
A dismissal referencing any duplicate resolves that logical report. Concurrent
valid dismissals choose the same canonical decision; a later report from a new
reporter/revision remains pending unless the target has been removed. Removal
closes pending review for every revision, and later reports cannot reopen it.
Removal wins over edits and review status.

Report records contain references and metadata, never a copy of target content.
Expiration of the target prunes dependent explanations and edits. Expired
controls intentionally retain minimal reference and resolution tombstones with
explanations scrubbed. These are durable anti-resurrection evidence, not retained
message content: duplicate reports, rebuilds, or late edits cannot reopen resolved
review or restore removed content.
Normal timeline, reply-preview, search, media, and review-detail content is
suppressed after removal. There is no withdrawal, undo, or restore operation.

The event write, modifier edges, per-message summary, logical reports, and queue
counts use the account database transaction rail. Publication failure follows
the existing local projection invalidation and retry behavior.
