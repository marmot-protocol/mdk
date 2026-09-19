# September 17 Hermes turn: approval wait and monitoring boundaries

Research Bead: `btq-harness-14a6f13fc94098f193888b89`. Analysis date: 2026-09-19.
No production behavior, approval decision, service, or watchdog was changed.

## Finding

The 15,420.6-second turn spent approximately 15,313.53 seconds in a terminal
operation that ended when shutdown interrupted its **approval wait**. This is
stronger evidence than the earlier diagnosis had: the seven model calls were
completed early in the turn. An unresolved approval is a supported explanation
for the stalled same-group dispatch; a four-hour model request is not supported.
Whether any later message reached the socket or was queued during that interval
remains unknown. The evidence does not establish a silent connector failure.

The empty inbound handler invocation after restart was an automatic resume of an
interrupted session. It is not evidence that a missed wire message was replayed.
Restart released the wait; that alone cannot identify a transport fault.

## Evidence and limits

Retained local logs are private source evidence, not attachments for publication.
The table intentionally omits chat, account, session and message identifiers,
commands, user text and tool output. Times below are the logs' local PDT times.

| Time on September 17 | Evidence | Implication |
| --- | --- | --- |
| 16:24:43.000 | `gateway.log:2122`, `agent.log:622–623`: handler and turn start | Downstream dispatch had begun. |
| 16:24:51–16:26:29.965 | `agent.log:627–643`: model calls numbered 20 through 26 in the continuing session | Seven completed calls in this turn; the numbering is session-wide. |
| 16:24:51–16:26:19.400 | Same region: six terminal results, including one error | The first six tool operations returned. |
| 16:26:30.076 | `agent.log:644`: auxiliary approval client selected | Approval processing follows the seventh call. |
| 20:41:43.035 | `gateway.log:2132–2134`: drain times out with one active agent; interruption requested | Turn remained active at shutdown. |
| 20:41:43.503 | `agent.log:1455`: approval wait interrupted, returning deny | Direct evidence of an outstanding approval wait. |
| 20:41:43.506 | `agent.log:1456`, `errors.log:9145`: terminal returns denial after 15,313.53 seconds | Subtracting duration gives approximately 16:26:29.976, matching the seventh call. No evidence that the denied shell command executed. |
| 20:41:43.520–.557 | `agent.log:1457`, `gateway.log:2136`: interrupted turn ends, seven calls, 15,420.6 seconds, empty response | Approximately 99.3% of elapsed turn time was inside the final terminal operation. |
| 20:41:49.408–20:41:50.045 | `agent.log:1554–1563`: auto-resume scheduled; empty handler preview; turn starts with shutdown-resume system note | The apparent post-restart inbound event is not proof of storage replay. |

Current `config.yaml` and retained `config.yaml.pre-durable-harness` both set
`approvals.timeout` to 43,200 seconds (12 hours). This is consistent with an
unexpired four-hour wait, but neither file proves the effective incident-time
configuration. Do not infer that the host's default timeout was in effect.
Pinned Hermes source `3ef6bbd201263d354fd83ec55b3c306ded2eb72a`,
`tools/approval.py:2493` and `:3115–3160`, reads that setting and polls for a
response/interrupt while refreshing activity. Current installed Hermes has
refactored this into `tools/approval_gateway_wait.py:_poll_event`, preserving
human-wait activity updates. Neither checkout is asserted to be the exact
incident executable. The log evidence identifies the wait independently.

No retained incident-time asyncio/thread stack was found in the inspected logs;
`gateway_faulthandler.log` was empty at inspection. The shutdown diagnostic file
contains raw process command lines and is unsuitable for public attachment.
The exact approval prompt, delivery outcome, user-response routing and effective
approval timeout at that moment remain unverified. Do not retry the denied
operation to investigate it, and do not treat shutdown's synthetic denial as
proof of an explicit user rejection.

## Reproduction, without live traffic

The locally installed monolithic adapter has SHA256
`dc83c0d10172e424ddf8c8ca27da03b38ab589f3fb6f2552867b79ff6bd443af`, matching the
previous diagnosis. Its `KeyedAsyncQueue` at lines 207–291 schedules tasks per
key, shields predecessor waits and has no execution deadline. Its inbound reader
explicitly disables the per-request timeout after ACK.

`python3 /tmp/mdk-hung-turn-repro.py` extends the earlier AST-extracted diagnostic
(`/tmp/mdk-wedge-repro.py`). Only the queue and inbound generator are compiled;
plugin initialization, sockets and account data are not accessed. Results:

- Start a suspended synthetic group A task; enqueue another A and a B task.
  B completes while A's second task stays behind its predecessor. Queue A depth
  is two (active plus waiting). Releasing A drains the queue in order.
- Capture bounded await-chain code names before releasing A: the active task is
  `_runner -> hung -> wait`; its follower is `_runner` awaiting its predecessor.
  No frame locals, task representations, source lines or identifiers are emitted.
- Synthetic receipt/admission counts advance to three; two dispatches start and
  one completes. This differs from an ACK-then-silent producer, where the mocked
  post-ACK read remains pending beyond `request_timeout` and explicitly receives
  `timeout=None`. A finite observation proves the code path, not an actual outage.
- Four scalar counterexamples below were checked against the proposed watchdog
  predicate. These are specification tests, not tests of an installed watchdog.

This reproduces queue isolation and the diagnostic distinction. It does not
reproduce the historical approval delivery failure or prove incident-time wire
receipt. No live task was triggered to generate traffic. Stack capture on a live
host remains a separately authorized implementation requirement.

## Watchdog review: specification, not deployed implementation

Maintenance Bead `btq-harness-0df13f499c20ed5f0b2d32fd` is still open. At inspection,
`~/.hermes/scripts/marmot-wedge-watch.py` was absent and the cron inventory had no
job of that name. The retained brief `/tmp/marmot-wedge-watch-task.md` and Bead
specification are therefore the review targets; operational prose saying it was
implemented is not verification. The enabled hourly backstop's prompt also uses
store-versus-handler freshness, so the conceptual defect has a separate consumer.

The proposed predicate is `newest_allowed_store_timestamp > last_handler + 300`.
An old handler timestamp is not itself a transport failure signal.

| Case | Predicate behavior | Correct interpretation |
| --- | --- | --- |
| Allowed sender, activation rejected or onboarding consumed | Can trigger although no agent handler should run | Intentional skip, not transport failure. |
| Message routed to a managed workstream instead of an agent | Can trigger despite successful delivery to its intended consumer | Track route outcome separately. |
| Approval wait or long-running same-group predecessor | Can trigger after a newer message | Queue/dispatch wait, not proven wire failure. |
| No later incoming message | Never triggers on a stuck turn | Need oldest active-turn and approval-wait ages independent of arrivals. |
| A stalls while B continues dispatching | Global newest handler masks A's backlog | Maintain bounded per-queue state internally, export aggregate maxima/counts. |
| One missed item at handler+299 seconds | Never triggers, even hours later | Timestamp difference is not the age of an outstanding item. |
| Stored event filtered by scope/type/self/dedupe | May have no corresponding handler | Compare eligible disposition, not all store activity. |
| Heartbeat stale | Separate process/event-loop suspicion | Not specifically a subscription failure; detector scheduling can also be stalled. |

Authorization is the host's full chain, not just a literal `.env` allowlist.
Timestamp clocks, timezone parsing, catch-up ordering and log rotation create
additional uncertainty. Absence of a parseable log baseline must be `unknown`,
not healthy or immediately wedged. Store scans can be incomplete or delayed.
Do not open the live account home with a second CLI for this detector; coordinate
storage safety separately. A read-only control request establishes only its own
responsiveness, not progress of the existing subscriber.

Two further specification corrections are needed before implementation:

1. Keep the last successful recovery timestamp through healthy ticks. Resetting
   `last_trigger` to zero on a healthy tick defeats the promised 900-second
   cooldown during intermittent failures. Use monotonic runtime intervals and
   define restart/clock-adjustment behavior for persisted wall times.
2. Record recovery intent before arming, then record the arm result. The addendum
   requests writing `armed_timer: true` before invoking systemd; that would claim
   success if arming failed or the process died. Bound and rotate the log. A
   separate bounded monitor heartbeat must prove ticks are running even when
   healthy chat output is silent.

## Proposed privacy-safe telemetry contract

This is a design, not installed instrumentation. Keep routing keys only in bounded
in-memory state. Export aggregate counts, maxima and fixed-bucket durations, with
fixed `target`, `method` and reason enums. No group/account/message/session IDs,
pubkeys, payloads, command text, endpoints, paths, stable hashes or task reprs.
Use monotonic time for ages; wall time is only for cross-log approximate ordering.
Counters reset with process lifetime; readers must recognize resets and missing
samples as unknown. Cap state by the same admission limits as the real queue.

| Boundary | Update point | Aggregate signals |
| --- | --- | --- |
| Wire receipt | After a complete validated frame, before awaiting any handler | Received count, last frame age, frame-kind enum; ACK tracked separately. |
| Inline control handling | Before/after awaited non-queued event handling | Active count, oldest handling age, completion/failure count. |
| Admission | Queue acceptance or rejection | Admitted/shed counts, pending and active counts, oldest pending age. |
| Disposition | Routing, activation, onboarding, authorization, duplicate decisions | Fixed outcome counts including routed, ambient, denied, duplicate and dispatchable. |
| Dispatch | Immediately before/after actual consumer call, with cleanup in finally | Starts/ends, active count, oldest turn age, cancellation/error outcomes. |
| Approval | Request registered, notification outcome, resolution/expiry | Pending count, oldest wait age, notify failures, timeout/deny/allow counts. No prompt data. |
| Tool/model wait | Actual wait transitions, separate from activity heartbeat | Active wait class, oldest age, last completed progress age. Human wait is not model progress. |
| Subscription | Open/ACK/read termination/reconnect scheduling | Connected count, ACK age, EOF/read error/resync/cancel/retry counters using safe enums. |

Receipt freshness can stay idle on a healthy quiet link. An ACK is not a lease;
without a same-subscription progress contract, label quiet transport `unknown`,
not failed. Liveness design belongs to sibling Bead
`btq-harness-fa7858117ffd9645d0c01d5f`. Do not introduce reconnect loops to solve an
approval wait. Approval controls need a separately reviewed path that cannot be
blocked behind the very turn they must resolve; this must preserve authorization
and never auto-approve on timeout or restart.

## Capture before recovery

Before any separately authorized watchdog restart, request a bounded diagnostic
snapshot with a short deadline. Record aggregates above and a capped histogram of
known code-location/wait-class tuples for asyncio tasks and worker threads.
Traverse coroutine await chains as well as task frames; an executor-backed agent
wait will not be explained by asyncio frames alone. Exclude locals, source text,
absolute filenames, task names, commands and exception strings. Use allowlisted
module/function labels or fixed wait enums. Unknown frames become `other`.
Write restrictive files, enforce byte/time/retention caps and note truncation.

If the event loop cannot service the snapshot, record `snapshot_timeout`; never
wait indefinitely before recovery. An external thread snapshot mechanism needs
explicit installation and authorization; do not send an unregistered signal to a
running Python process. Preserve the snapshot before arming recovery, then record
the arm result and post-restart delivery verification separately. A green service
or auto-resume log is not proof of replay.

Acceptance tests for a future implementation: A blocked/B advancing; quiet healthy
stream; ACK silence; blocked inline handler; queue saturation; routed/ambient/denied
messages; pending human approval; missed message inside the 300-second margin;
clock jump/log rotation; failed snapshot and failed timer arm; cooldown across
healthy ticks; counter reset; privacy canaries in all identifiers and frame locals.
Use isolated fakes and captured operations, not live traffic or real restart timers.

## Ownership and next boundary

The analysis is complete; historical approval delivery details remain unavailable.
Host approval/queue diagnostics and watchdog corrections must be coordinated with
maintenance run `b61d651b-8206-52d9-8965-d30d937dd103`, especially its watchdog Bead
`btq-harness-0df13f499c20ed5f0b2d32fd`. Implementation and deployment require a
separate authorized boundary. Coordination review is filed as
`btq-harness-52fc95b283df4f76d273a5e4` for manager routing to maintenance.
No fix is implied by this research document.
