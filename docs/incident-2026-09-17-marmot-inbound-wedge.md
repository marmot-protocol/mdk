# Incident 2026-09-17: silent Marmot inbound-wedge diagnosis

Bead: `btq-harness-8e0136b53f133d6b37a431d0` (workstream `mdk`).
Question investigated: did wn-agent stop delivering events?

---

# Inbound-wedge diagnosis — btq-harness-8e0136b53f133d6b37a431d0

## Result

The available evidence does **not establish that wn-agent stopped delivering events** during the 2026-09-17 incident. There is a confirmed end-to-end liveness/observability gap, and a confirmed 15,420.6-second Hermes turn spanning the incident. A hung same-group turn is a supported alternative explanation for absent gateway inbound logs. Neither an exact producer failure nor the cause of the hung turn can be recovered from the surviving logs. No speculative production fix was made.

## Evidence and revision boundaries

- Diagnosis checkout: base `8107b3c7`, isolated branch `bead/2c08f79f-8ceb-553d-9dc6-d2f9408cf489/btq-harness-8e0136b53f133d6b37a431d0`, clean. Repository file/line references below refer to that base.
- Deployed adapter: `/home/openclaw/.hermes/plugins/marmot/adapter.py`, SHA256 `dc83c0d10172e424ddf8c8ca27da03b38ab589f3fb6f2552867b79ff6bd443af`. It is a locally modified, monolithic adapter, unlike the checkout's split modules and durable inbound spool. Do not infer deployed behavior solely from current main.
- Running wn-agent: PID 9193, service active since September 16 15:40:37 PDT; `/proc/9193/exe` points to `/home/openclaw/.local/bin/wn-agent`. Installed binary reports `0.9.19`, SHA256 `45379b05f6cfa6f4a54715111d69d0843c48d132ad45557e97784357bc5d07eb`. A version string does not identify its exact source commit; that mapping is unavailable here.
- `/home/openclaw/.hermes/logs/gateway.log:2122`: inbound handler starts at 16:24:43. Lines 2123–2124: response sends at 16:27:56 and 16:28:14. Lines 2131–2136: shutdown still has one active agent and interrupts it; `response ready` reports `time=15420.6s api_calls=7 response=0 chars` at 20:41:43. This proves a long-lived turn, not where its underlying tool/model wait was stuck.
- Gateway reconnect succeeds at 20:41:48 (line 2163); a handler starts at 20:41:49 (line 2170). That entry has an empty text preview; without message identity correlation it is not proof that a particular missed text message was replayed.
- The operational incident reference itself says the newest store item at 20:30 was the 16:24 item. That item had already reached the gateway log at 16:24:43. Unread state and chat activity timestamps alone do not prove later inbound events were missed. Fresh heartbeat/connected state likewise does not prove stream progress.

## Source trace and candidate assessment

1. Relay boundary: `crates/marmot-app/src/relay_plane/mod.rs:1626` handles SDK websocket notifications; line 1658 forwards them to the Nostr transport adapter. Account processing produces sync summaries; `runtime/account_worker.rs:5121` publishes summaries, and `:5266`/`:5287` broadcasts `MessageReceived`. This broadcast is a live notification layer, distinct from durable account storage.
2. Connector projection: `crates/agent-connector/src/inbound.rs:35` subscribes to runtime/debug/catch-up channels, ACKs, and runs initial catch-up concurrently (`:45`). `event_projection.rs:625` projects runtime messages; `:642` reads the authoritative durable row before exposing content. Scope/self/event filtering can intentionally produce no output. Synchronous hydration/storage reads are inside the event-loop branch: a blocked synchronous read would suspend this connection's progress and is not covered by the socket write deadline. No incident evidence proves such a block.
3. Lag is **not silently ignored for user messages**: `inbound.rs:141–222` handles runtime lag with bounded durable replay or `resync_required`; replay errors also emit resync. Runtime channel closure returns at `:223`; catch-up closure returns at `:101`. The connection then drops its socket halves in `connection.rs:62–126`, allowing client EOF. Debug lag/closure is ignored (`inbound.rs:226–237`), but this is a separate debug-only source whose sender the connector retains; it is not evidence of silently dropped production messages.
4. Socket backpressure is bounded in current source: `connection.rs:30–59` wraps frame writes and flushes in a timeout; `lib.rs:79` sets 15 seconds. Timeout escapes the inbound loop, drops the connection, and `lib.rs:462–474` emits a privacy-safe warning. Therefore an ordinary asynchronous blocked socket write is not an unbounded stall in this revision. These timers cannot preempt synchronous blocking or a starved runtime, and the installed binary's exact revision is unverified.
5. Catch-up completion is not a wire heartbeat: `inbound.rs:97–104` consumes it internally. There is no periodic application heartbeat in the subscription loop. Initial catch-up can wait while the main loop continues receiving; it does not hold up the drain loop. A separate socket ping would establish control-service responsiveness, not progress on this subscription or the relay/store path. `inbound.rs:74–77` explicitly warns that adding requests to the existing read-only stream requires cancellation-safe framing first.
6. Python wire reader: repository `integrations/hermes/marmot/agent_control.py:632`, deployed adapter `:1675`, explicitly reads with `timeout=None` after ACK. No event, EOF, or exception means it can wait indefinitely. Reconnect only runs after termination/error (`adapter.py:3120`, deployed `:3554` approximately); there is no positive stream-liveness contract.
7. Consumer work can also stop reads: repository `adapter.py:3194`, deployed `:3628`, awaits `_handle_control_event` before requesting another event. Mutation/group-state handlers are inline and need their own progress diagnostics. Ordinary user turns are enqueued, not awaited there (deployed `:3696`). The deployed `KeyedAsyncQueue` waits on the predecessor at `:254`, then runs the next task at `:257`, with no execution deadline. A hung turn blocks later turns for that group, not other groups or the normal socket reader. Dispatch calls the gateway at `:3851`/`:4054`; routing to managed workstreams also happens inside this queue (`:3726–3744`) and therefore cannot bypass a prior blocked turn.
8. The supposed receive timestamp is downstream: installed Hermes `gateway/run.py:21231–21243` emits `inbound message` inside `_handle_message_with_agent`, not at the socket reader or queue admission. It is unsuitable as a sole measure of transport delivery. The confirmed long turn and FIFO behavior explain why this metric can stay unchanged despite a working stream. Cross-group test traffic, socket receive timestamps, queue depths/ages, and task stacks were not captured during the incident.

## Logging recommendation

Current connector source already contains lag/projection/write-failure tracing, but normal subscription lifecycle has no progress evidence. The user service journal is empty for the inspected 16:00–21:00 interval. Direct subscriber initialization was not found in the inspected wn-agent entrypoint/connector/app code; verify the effective tracing sink in a subprocess before merely adding more tracing calls. Add tested, privacy-safe subscription open/close/reason counters and last successful delivery/heartbeat ages, and consumer wire-receipt, queue-admission, handler-start/end ages. Do not log payloads, identifiers, relay endpoints, or sensitive paths. Aggregate logging should distinguish an idle connection from an advancing queue with a blocked handler.

## Validation

`python3 /tmp/mdk-wedge-repro.py` passed two deterministic checks using AST-extracted code from the deployed adapter (no importing its plugin initialization, live sockets, or account data):

- A suspended group A turn blocks its second turn; group B proceeds; releasing A permits its second turn.
- An ACK followed by silence stays pending past the configured request timeout; the actual generator passes `timeout=None` to its read. The finite test confirms the behavior and code path, not a historical stall.

The script is a diagnostic reproduction, not an end-to-end incident reproduction. No production source changed, so no cargo/fast-ci build was needed or performed. No signed commit, push, deployment, account database opening, or service restart was performed.

## Follow-up and watchdog interplay

File separate work for (1) incident/host-turn evidence and accurate receive-versus-dispatch monitoring, and (2) a compatible subscription liveness contract plus lifecycle logging. Root cause remains unresolved; implementation needs a task boundary and reviewable design. A naive quiet-stream timeout would repeatedly reconnect healthy idle subscriptions and does not fix a blocked group queue. Reconnect also must not be assumed to guarantee a full storage replay: the reviewed connector explicitly replays on lag, while subscription setup requests catch-up; replay guarantees need integration tests, including dedupe and already-processed rows.

The `marmot-wedge-watch` stopgap can recover some failures by restarting the gateway, but comparing store timestamps with downstream handler logs conflates stream failure with queue/turn stalls and activation/routing. In this incident, an old unread item is not sufficient evidence for either. Keep cooldown/startup guards; separately measure wire receipt and queue age, and capture stacks before restart. Its 300-second newer-store threshold may not detect a long-running turn if no later incoming item exists. Do not claim the watchdog proves root cause.

Any later deployment is separate: use matching CLI/wn-agent builds for a shared Marmot home to avoid schema-version skew, then coordinate the appropriate service restart. This diagnosis touched no live service or shared account state.

Filed follow-up Beads (not claimed or executed):
- `btq-harness-14a6f13fc94098f193888b89`: hung-turn evidence and receive-versus-dispatch monitoring; coordinate with hermes-maintenance watchdog work.
- `btq-harness-fa7858117ffd9645d0c01d5f`: subscription liveness design, replay guarantees, and verified lifecycle diagnostics.
