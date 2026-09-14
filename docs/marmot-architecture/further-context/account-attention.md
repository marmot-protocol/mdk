---
title: "Independent account attention"
created: 2026-09-14
updated: 2026-09-14
status: implementation
---

# Independent account attention

C4 M3 in [#1777](https://github.com/marmot-protocol/mdk/issues/1777) adds
`MarmotAppRuntime::subscribe_account_attention()`. An account switcher can receive
current badges without opening a chat list or starting that account's worker.
This reuses the durable chat counters and M1 eligibility keys; it adds no migration
or second counter store. Native bindings follow in M4.

## Snapshot contract

The initial response and subsequent updates are complete `AccountAttentionSnapshot`
replacements with a subscription generation and increasing sequence. A slow consumer
receives the latest replacement; skipped sequences are normal. Accounts are ordered
by stable identity. Each account is individually coherent, with no simultaneous
transaction across account databases.

Each signed-in local or external-signing account has either:

- `Ready`: unread messages, unread mentions, conversations needing attention, and
  manual-only conversations. `has_unread()` means at least one eligible conversation.
- `Unavailable`: `Preparing` for incomplete base rows or onboarding, `Resetting` during
  account teardown, or `ReadFailed`. These states carry no invented zero or stale total.

An unreadable account catalog produces an error for the subscription as a whole,
with a retained retry obligation. It never silently removes an unreadable account
record. Signed-out and deleted accounts are removed after catalog reconciliation;
new and reactivated accounts appear even without a running worker. Catalog reads
hold the shared `AccountHome` mutation lock; metadata-probe errors
also propagate rather than treating an inaccessible catalog as an empty one.

`recv()` is cancellation-safe. Dropping the subscription ends its actor. Runtime
shutdown or terminal storage close ends delivery. A reopened subscription receives
a new generation. Low-level callers that mutate `AccountHome` directly must call
`reconcile_accounts()` to notify the runtime of catalog changes.

## Eligibility and work

One SQLite statement checks missing base rows and aggregates the same predicate as
Unread: `list_scope = 0 AND list_unread = 1`. It explicitly uses the existing partial
Unread index, so work scales with eligible unread conversations, not all conversations
or retained history. It sums stored counts without converting chat rows, loading
rosters, opening MLS sessions, or reading message DTOs.

Pending invitations, archived chats, and Left conversations do not contribute.
Durably queued leave/disband requests use the same suppression as the four-list
contract; cancellation/failure restores eligibility when the existing operation
state permits it. Muted active conversations still count. Manual unread can add
one attention-only conversation but never a message or mention. Acceptance reveals
retained eligible counts without marking history read.

Cold account-state import remains a one-time prerequisite. Missing base rows use
one existing bounded preparation batch per attempt, then report `Preparing` until
complete. No selected-presentation preparation or legacy full-list warm is needed.
The ready aggregate's bounded work does not imply a constant-time cold import.

## Invalidation and recovery

Sources attach before the initial catalog/database reads. The actor caches only
aggregate states and the account catalog. Normal changes refresh the affected
account; catalog-only changes do not reread unchanged ready accounts.

| Committed change | Notification consumed |
| --- | --- |
| Messages, mentions, edits/deletes, read markers, manual unread | Runtime projection updates |
| Invite acceptance, archive, membership, queued departure and reversal | Runtime projection/group-state updates |
| Base-row preparation and presentation maintenance | Account-scoped presentation invalidations |
| Creation/import, external login, sign-in/out, removal/reset, onboarding | Catalog notification and account-reset notifications |

Queued notifications coalesce before reads; notifications arriving during a read
remain queued. Broadcast lag triggers a fresh aggregate reconciliation. Unavailable
accounts retry without new traffic, with independent exponential delays from one
second up to 30 seconds. Successful base-row preparation and relevant external
invalidations reset that account's delay; unrelated account traffic does not.
Catalog failures back off separately and retain all aggregate refresh obligations.
A per-account retry reads only that account: it does not enumerate the catalog.
Ready accounts are not polled. Mute deadlines need no timer because
mute does not change attention eligibility.

## Compatibility and evidence

The existing `account_unread_summary()` and its native record layouts remain. Their
counters now share Unread eligibility, intentionally suppressing pending invitations
and queued departures. The old getter retains local-signing account enumeration,
legacy readiness, and omission of failed account reads. Consumers needing explicit
availability and independent live updates should adopt this additive API through M4.

Storage tests compare totals with Unread across invite/archive/membership/manual/mute
combinations, exercise departure rollback, and count SQL VM work with 4,096 chats and
5,000 retained messages. Runtime tests cover isolated account refreshes, initial-read
races, message/mention changes, account lifecycle, lag recovery, unavailable states,
retry without traffic, cancellation, and shutdown. These are local correctness/work
checks, not device latency measurements or native adoption evidence.
