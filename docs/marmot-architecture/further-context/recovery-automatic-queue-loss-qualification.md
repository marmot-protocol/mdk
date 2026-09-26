---
title: Automatic account QueueLoss recovery qualification
created: 2026-09-26
updated: 2026-09-26
status: Focused local qualification
---

# Automatic account QueueLoss recovery qualification

The account worker now keeps an eligible singleton QueueLoss grant while its
immutable SDK reconciliation request and bounded event queue run in the shared
recovery job. Direct overflow Receive, ordinary Receive, and Maintenance use
the same frozen owner grant. Only plans within four routes and four endpoints
per route offload; an ineligible plan executes that same grant inline. When the
shared credit pool is empty, an eligible QueueLoss shape defers before retry
reservation. Activation, admission, drain, checkpoint, and loss acknowledgment
remain with the account owner. Shutdown aborts and reaps owned network/queue
tasks; the loss guard preserves unacknowledged delivery loss. An owned
direct-overflow completion resumes the original Receive tail after
reporting its real summary: pending projection updates, visible post-join
history, subscription refresh, convergence scheduling, audit/push work, and
the existing error/reconnect path. A completed overflow also runs the
post-replay Receive arm for newly pending recovery debt; incomplete and
deferred outcomes retain their debt for a later seam.

The focused fixture uses two local relays, the real Nostr SDK transport,
SQLCipher account storage, and valid MLS history. Bob fills Alice's 1,024
ordinary-delivery slots, then publishes a valid group-profile commit as the
first omitted event and two dependent custom messages. The router records a
real drop and durable typed QueueLoss evidence. A test-only worker pause
stabilizes the pre-burst boundary; it does not select a grant. The fixture
observes the naturally selected QueueLoss attempt and its persisted target
route/time bounds. It holds the exact-ID acquisition for the missing commit
at the local relay, then checks a status read within 300 ms, a healthy-route
send within 2 s, and a separate healthy live delivery within 2 s. The hold
releases immediately after concurrent probes, before scope inspection.

Both local paths passed: a naturally selected Maintenance attempt and a
Receive attempt reached by one additional valid healthy-route delivery once
the ordinary queue had capacity and no network job was active. That condition
does not establish that an earlier grant had completed. At the hold, the
selected network job and adapter request remained active through all probes.
After release, that attempt returned and queued the target event; no later
grant was selected before the missing commit was durably retained, Alice
advanced one MLS epoch, and both dependent plaintext messages appeared. The
durable QueueLoss marker and
demand remained pending because the SDK's EOSE and aggregate comparison do
not certify exhaustive admission. The fixture asserts the loss stays honest.

This is a focused local outcome, not proof for every account route shape,
continuous traffic, relays without comparison support, process restart, or
device delivery. The SDK's per-route negotiation and acquisition deadlines,
the outer 10-second network quantum, and existing drain clocks were unchanged.
The fixture gates the SDK's exact-ID acquisition and records the active client
attempt, per-route comparison counts, and remaining outer deadline. A selected
scope alone does not establish that an exact-ID request was issued or that the
missing event was admitted. Failed relay comparisons and unattempted suffixes
remain partial coverage with durable debt; they are not successful recovery.
