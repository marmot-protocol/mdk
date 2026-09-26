---
title: Periodic comparison worker resume
updated: 2026-09-25
status: Narrow execution slice
---

# Periodic comparison worker resume

The existing 15-second maintenance arm can now suspend one owner-selected
transport comparison while its SDK network request runs. The account worker
first authorizes a single frozen grant and installs the live and maintenance
subscriptions. An immutable task then compares at most four selected routes,
each with at most four already-admitted endpoints. The worker's main select
continues to serve commands and ordinary delivery while that task waits.

The task owns only the route/inventory snapshot, account adapter handle, and a
memory-only advisory replay cursor. It cannot write SQLCipher, submit a relay
event to the account queue, mutate the MLS engine, or settle the grant. On
join, the worker checks the selected loss, route, inventory and obligation
revisions, comparison revision and attempt serial, and account subscription
attempt. A stale result is discarded in full. For a current result, the worker
submits the returned event batch under one fresh, finite 10-second admission
window shared by all selected routes. This can add up to 10 seconds after the
SDK acquisition quantum while the same capacity credit remains held. A route's
proposed cursor is saved only after its entire owned batch enters the ordinary
queue. If submission stops, the prior cursor stays durable, the route retains
retry debt, and an already queued prefix may recur on the next pass. The worker
then drains, checkpoints, settles and reports through the existing owner path.

The cursor records attempted exact IDs, not admitted events. A completed
non-single-object byte-limited SDK acquisition that returned no requested ID
can restore its prior cursor; a deferred large ID can therefore lead the next
pass. Cancelled tasks lose their memory cursor and retry the still-durable
comparison debt. A completed partial pass may rotate past a refused prefix,
including routes that returned no events or handed off their complete batch,
but an unretained event remains in the comparison difference and recurs when
rotation wraps. This worker handoff supersedes the earlier recommendation in
`recovery-worker-resume.md` to durably acknowledge a cursor before SDK fetch:
the worker now persists the final advisory cursor only after joining a current
task, while durable event inventory alone controls admission.

The off-worker shape uses the existing two process-wide recovery credits. A
credit is acquired before owner reservation and held through worker admission
and checkpoint. More than four endpoints, a different selected cause, or an
unsupported grant uses the same frozen grant on the existing inline executor
with every endpoint intact. Credit exhaustion defers a comparison-only attempt
without spending retry cost; independent selected demand keeps its inline
path. The limits bound selected task shape and SDK result policy, not full
wire traffic, temporary conversion copies, total process RSS, or the live
subscription's traffic.

Startup and explicit catch-up comparison waits remain inline. Eligible
scheduled post-convergence and ordinary receive comparisons can use this same
job boundary after their local work; see
[post-convergence comparison resume](recovery-post-convergence-comparison-resume.md) and
[receive comparison resume](recovery-receive-comparison-resume.md).
Activation, group registration, SDK drain and checkpoint can still hold the
worker. The inactive bounded known-event worker remains gated separately. No
release version, schema or subscription policy changes in this slice.

An explicit catch-up arriving while a comparison task is active
waits in the worker's command FIFO until that task joins. Later mutations stay
behind it, while read-only status commands can still run during the SDK wait.
