---
title: "Independent account attention"
created: 2026-09-14
updated: 2026-09-15
status: implementation
---

# Independent account attention

C4 M3 in [#1777](https://github.com/marmot-protocol/mdk/issues/1777) adds
`MarmotAppRuntime::subscribe_account_attention()`. An account switcher can receive
current badges without opening a chat list or starting that account's worker.
This reuses durable chat counters and eligibility keys, with no second counter store.
Migration 0074 adds an indexed invitation key maintained from authoritative account state. [Native bindings and handoff](chat-projections-native.md) are provided by M4.

## Snapshot contract

The initial response and subsequent updates are complete `AccountAttentionSnapshot`
replacements with a subscription generation and increasing sequence. A slow consumer
receives the latest replacement; skipped sequences are normal. Accounts are ordered
by stable identity. Each account is individually coherent, with no simultaneous
transaction across account databases.

Each signed-in local or external-signing account has either:

- `Ready`: unread messages, unread mentions, conversations needing attention, and
  attention-only conversations (pending invitations and manual-only reminders). `has_unread()` means at least one eligible conversation.
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

One SQLite statement checks missing base rows and aggregates two disjoint indexed sets:
Unread rows (`list_scope = 0 AND list_unread = 1`) and active pending invitations
(`list_scope = 0 AND list_pending_invite = 1`). Work scales with eligible attention
rows, not quiet/archived/Left conversations or retained history. No rosters, MLS
sessions, message DTOs or selected presentation are loaded.

Each unarchived pending invitation adds **one** `attention_only_conversations` item,
even with retained messages or a manual reminder. Its message and mention counts
remain suppressed until acceptance. The **Unread filtered list still excludes invites**.
`unread_conversations` counts all eligible attention rows and `has_unread()` includes
invitation-only accounts. The application badge is
`unread_count + attention_only_conversations`.

Archived chats and Left conversations contribute nothing. Durably queued leave/disband
requests use the same suppression as the four-list contract; cancellation/failure
restores eligibility when existing operation state permits it. Muted active
conversations still count. An accepted manual reminder adds one attention-only item
only when there are no unread messages. Acceptance replaces invitation attention with
retained eligible counts without marking history read. Source-state changes update
the invitation key transactionally, even before a display-row refresh.

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
| Invite arrival/acceptance, archive, membership, queued departure and reversal | Runtime projection/group-state updates |
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
counters use the same attention policy, including pending invitations and suppressing
archived chats and queued departures. The old getter retains local-signing account enumeration,
legacy readiness, and omission of failed account reads. Consumers needing explicit
availability and independent live updates should adopt this additive API through M4.

Storage tests distinguish attention totals from Unread across invite/archive/membership/manual/mute
combinations, exercise departure rollback, and count SQL VM work with 4,096 chats and
5,000 retained messages. Runtime tests cover isolated account refreshes, initial-read
races, message/mention changes, account lifecycle, lag recovery, unavailable states,
retry without traffic, cancellation, and shutdown. These are local correctness/work
checks, not device latency measurements or native adoption evidence.
