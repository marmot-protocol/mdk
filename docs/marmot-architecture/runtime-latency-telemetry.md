---
title: "Conversation readiness and runtime latency telemetry"
created: 2026-09-18
updated: 2026-09-23
status: implementation
tags: [marmot, runtime, telemetry, performance]
---

# Conversation readiness and runtime latency telemetry

These measurements distinguish local conversation content, engine authority, worker contention
and message publication. They observe existing behavior; they do not prioritize conversations,
change catch-up/reconnect policy, retry sends, or alter readiness deadlines.

## Accounting and export

`AppPerformanceSnapshot.runtime_operations` and its UniFFI/C mirrors contain one entry for
every closed `RuntimePerformanceOperation`, including zeroes before first use. No operation
accepts arbitrary names or identifiers. OTLP emits `app_runtime_<operation>_<suffix>` with no
per-operation attributes, account/group/message identifiers, relay labels, payloads or SQL.
The existing resource metadata and revocable diagnostics consent still apply.

Each operation has these suffixes:

| Suffix | Meaning |
| --- | --- |
| `started`, `completed` | Cumulative starts and terminal outcomes |
| `successes`, `failures`, `cancelled`, `timeouts`, `not_ready` | Mutually exclusive terminal counts; their sum is `completed` |
| `duration_ms` | Fixed-bucket elapsed duration for all terminal outcomes, including cancellation; not a success-only percentile |
| `in_flight` | Current active observations, including queued work |
| `oldest_tracked_in_flight_ms` | Age of the oldest retained active start |
| `untracked_in_flight` | Active observations beyond the bounded age slots |

RAII observations record cancellation when a future or queued command is dropped. Started minus
completed equals in-flight within the process; an exporter consent baseline can exclude older
starts, so do not derive live gauges by subtracting exported cumulative counters. Process death
cannot emit cancellation. Age tracking retains at most 64 starts per operation, with exact counts
beyond that bound. The oldest tracked age is a lower bound during overflow. No per-open history
is persisted. Export snapshots require a functioning runtime/exporter; a process-wide stall may
also delay exporting these observations.

Storage, lower-level ingest phases, trigger counters and host-reported timings are completed-only:
start and completion are recorded together, so their live gauges remain zero. Their containing
runtime observations show unfinished work. Export uses the existing consent-period baseline;
fixed runtime series exist from its first snapshot so the first later observation is retained.

Completed-only recording uses per-operation atomic counters and histogram buckets, without the
live-observation mutex. Snapshot fields are sampled independently: a concurrent completion can
straddle the outcome and histogram reads, so those totals can differ temporarily. No samples are
lost; quiescent snapshots agree. Live observations use a separate mutex per closed operation.
Storage without an installed observer skips timing clock reads and the observer mutex entirely.

## Boundaries

Names below omit `app_runtime_` and the suffix. Durations nest and overlap: **do not sum them**.

| Operation | Boundary |
| --- | --- |
| `conversation_open` | MDK window-open entry to initial local snapshot/handle return, or error/cancellation |
| `conversation_local_read` | Blocking local account snapshot read, including scheduling and subsequent presentation |
| `conversation_worker_acquire` | Each worker-acquisition attempt; excludes the one-second gap between retries |
| `conversation_authority_attempt` | Each cold authority capture attempt, including worker availability/channel wait; distinguishes not-ready and the existing 50 ms timeout |
| `conversation_capture_queue` | Capture channel admission through worker dispatch/rejection/drop; a timed-out caller can leave a cancelled request queued until dispatch |
| `conversation_capture` | Worker-side authority/account capture; excludes response transport and presentation |
| `conversation_presentation` | Preparation of header, messages, identities and draft for a snapshot, including blocking-task scheduling |
| `conversation_authority_ready` | After open admission checks to the first prepared snapshot carrying live authority; stays active across retries; rejected opens do not start this wait |
| `conversation_send_ready` | Same start, successful when the first authoritative snapshot permits sending; finishes not-ready if that authority disables sending (membership/lifecycle), rather than reporting an indefinitely stuck open |
| `draft_send_caller`, `direct_send_caller` | Account-manager send entry through worker response, including acquisition and queueing |
| `send_worker_acquire` | Send's worker lookup/reconciliation |
| `send_admission` | Send channel admission wait |
| `send_queue` | Channel admission start to worker execution; includes admission wait, excludes worker acquisition |
| `send_execution` | Worker-side direct/draft send through completion of publication and projection work |
| `worker_acquire` | General worker lookup/reconciliation, across callers |
| `lifecycle_lock_wait` | Wait for the account manager's lifecycle transaction lock |
| `account_startup`, `worker_reopen` | Initial/reconnect runtime client open; existing account stage metrics provide additional subdivision |
| `account_startup_retry_suppressed` | Zero-duration completed-only `not_ready` count for each eligible account whose trigger was deferred by the worker-start cooldown |
| `worker_hydration` | Nonempty startup hydration pipeline, including command service between slices |
| `worker_catch_up` | Worker catch-up including the preceding frozen read snapshot and coalescing |
| `worker_snapshot` | Frozen group read snapshot immediately before catch-up |
| `worker_convergence`, `worker_maintenance` | Selected convergence/periodic maintenance work after no-work/shutdown skip checks; success means branch completed, not that every internally handled sub-operation succeeded |
| `worker_receive` | Received delivery/overflow handling through ingest result; excludes waiting for network input and subsequent worker postprocessing |
| `worker_reconnect_wait` | Reconnect backoff, including commands served/rejected during that wait |
| `ingest` | Account ingest and resulting effect publication; excludes subsequent app projection work |
| `ingest_engine`, `ingest_effect_publish` | Completed session ingest and completed publication of its returned effects, separately; publication can have no effects |
| `projection_checkpoint` | App state checkpoint and associated chat-list projection persistence |
| `storage_connection_wait` | Shared account connection acquisition, including transaction-owner wait |
| `storage_transaction` | Entire account transaction including ownership wait, begin, closure, commit/rollback; nested transactions also report |
| `storage_write_begin` | SQLite `BEGIN IMMEDIATE`, including existing busy retries |
| `catch_up_requested` | Explicit account-manager catch-up call |
| `catch_up_after_mutation` | Command helper's post-mutation catch-up (does not cover every creation/invite background task) |
| `catch_up_coalesced` | Zero-duration count of requests folded into an existing worker catch-up |
| `reconnect_command_rejected` | Zero-duration count of ordinary commands dropped while no engine exists during reconnect; preserves existing caller behavior |

Storage observers attach to the cached account connection after worker client open and again
on reconnect. They cover subsequent engine and projection access through that connection, not
initial database opening, shared/directory databases, or independent notification processes.
Callbacks aggregate only and must never access storage or perform I/O. Connection-wait and
transaction durations reveal contention but do not identify a particular query or conversation.

Existing `app_account_open_failures` now receives bounded failure-stage/error-class
classification from actual account-worker readiness attempts. The separate
`app_runtime_account_startup_retry_suppressed_not_ready` counter records deferred trigger
decisions, not unique accounts or elapsed cooldown time. It carries no account label or
failure text. Existing outbound queue, execution, local acceptance,
local projection, publication and caller-response metrics now also cover draft sends. Compare
build cohorts separately: increased outbound sample coverage is not itself a performance regression.
Publication success retains the existing required-ack semantics, not recipient delivery semantics.

## Native app integration

MDK cannot observe a rendered frame. Swift/Kotlin/C hosts should record each new milestone once
per open attempt using `record_host_performance` and a monotonic clock started at the navigation
intent:

- `ConversationLocalVisible`: first rendered local conversation content.
- `ConversationComposerReady`: first rendered enabled composer backed by authoritative `can_send`.

These map to `host_conversation_local_visible` and `host_conversation_composer_ready`. On a
failed/abandoned attempt, submit `Failure`, `Cancelled`, `Timeout`, or `Unavailable` as appropriate,
with elapsed time from the same start. `Unavailable` maps to `not_ready`. Do not manufacture
success on receiving a DTO or merely finishing relay sync. After an authoritative disabled
composer, close that open attempt as unavailable; a later user action can start a new attempt.
Other legacy host operations still aggregate all non-success outcomes as failures.

The binding surface is provided here; native call-site adoption and device validation are separate
work. Host milestones have no live start API, so unfinished native rendering itself is not visible
until a terminal host report. SDK authority and send gauges remain available while MDK waits.

## Reading the evidence

Compare platform and exact build cohorts. First inspect open/authority/send caller counts,
cancellation, timeout/not-ready rates and live ages, then the contained queue, execution, ingest,
checkpoint and storage timings. A long queue with a short execution suggests serialized work
rather than slow send processing; long effect publication can hold the worker after engine ingest
has finished. These are population correlations, not per-conversation causal traces.

Use targeted tests to prove a proposed behavior change separately. In particular, instrumentation
of reconnect rejection or repeated cold-authority timeouts is not a claim that either accounts for
every pending message or unavailable conversation.
