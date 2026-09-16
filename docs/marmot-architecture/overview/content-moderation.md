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
`delete_message` sends kind 4891 for an eligible active admin removing a whole chat
message and all its revisions, including their own chat. Otherwise it sends kind 5
for author self-retraction. Cross-author removal is limited to kind-9 messages:
stream starts, agent activity/operations, system events, and custom-kind rows are
no longer admin-removal targets. Completed agent messages remain ordinary kind-9
targets.
An author's already-removed or invalidated target can still be retracted with
kind 5 when it is no longer available for moderation. This preserves the existing
removal outcome and attribution.
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

## Authority and persistence

Moderation uses authenticated source-state policy, including branch provenance,
rather than current admin status. Unresolved authority stays retryable; resolved
verdicts survive restart, and convergence invalidation withdraws their effects.
Reports do not extend target retention or retain a second copy of its content.

See [implementation details](../further-context/content-moderation.md) for source
snapshot recovery, durable retries, incremental projections, and retention.
