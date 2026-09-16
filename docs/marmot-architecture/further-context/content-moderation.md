# Content moderation implementation details

See the [behavior overview](../overview/content-moderation.md) for the runtime
boundary and client compatibility requirements.

## Authenticated authority

The engine derives `AppMessageAuthority` from the MLS state used at encryption
or authenticated receive. It binds the verdict to a SHA-256 digest of that
state's epoch authenticator, and records active-member admin authority.
This evidence is local metadata, never an author-supplied event claim.

The branch digest is retained with moderation verdicts as provenance of the
policy decision, including when the original source snapshot has been pruned.
It is not an admin credential or an alternate branch-selection input. Ordinary
chat, reaction, edit, and author-deletion events omit this evidence; only the
two admin control kinds pay for its member/policy lookup and persistence.

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
to prove admin authority must not exempt dismissal explanations from expiry.

A separate durable retry record retains the source ID, sender, epoch and payload
digest without plaintext. Only kinds 1985 and 4891 enter this path;
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

Migration 0078 adds source-authority metadata, one indexed row per report event,
and a durable cursor over the existing event prefix. Account history and legacy
kind-5 deletion verdicts remain untouched. Historical admin controls begin with
unresolved authority and are re-evaluated against their authenticated source state.

Maintenance advances at most 100 old events per batch. Normal receive updates
only affected targets through modifier edges. Report lookup is indexed by group,
message, and report ID; pagination is exclusive and capped at 100. Dismissal labels
are read from the existing indexed event/edge store with source authorization,
without a separate resolution table. Multiple labels remain independent.

Report records contain identifiers, authors, category and timestamp. Explanation
text is read from its retained event; no target plaintext or attachments are
copied. Reports and labels expire independently under ordinary message retention.
Target deletion or expiry does not erase report explanations. Only deletion
controls retain minimal structural evidence after expiry, with unrelated tags
removed. Target replay fences exist only where retained deletion evidence needs
them; ordinary chat and report traffic does not create a moderation tombstone
ledger.

The event write, modifier edges, affected message projections, and report index
commit in one account transaction. Publication failure follows existing local
projection invalidation and retry behavior. `has_reports` is an indexed existence
check, not a counter or shared workflow state. There is no dedicated review queue
subscription; clients use existing projection events to refresh their own views.
