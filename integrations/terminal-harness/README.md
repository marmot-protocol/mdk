# Marmot Terminal Harness

`marmot-terminal-harness` is the shared Rust runtime behind
[`wn-claude`](../claude/marmot), [`wn-codex`](../codex/marmot),
[`wn-opencode`](../opencode/marmot), and [`wn-pi`](../pi/marmot). It keeps the
Marmot-facing behavior of pure terminal connectors consistent while leaving
backend command construction and event parsing in each connector crate.

The crate owns the `wn-agent` control client, account and sender selection,
inbound reconnect and resync, per-group bounded queues, deduplication, working
directory selection, private group-to-session mappings, reply chunking, and a
shared JSONL child-process runner. It does not own MLS, Nostr transport,
storage, QUIC previews, or backend-specific CLI semantics.

## Contents

- [Backend Boundary](#backend-boundary)
- [Execution Profiles](#execution-profiles)
- [Shared Behavior](#shared-behavior)
- [Chat Commands](#chat-commands)
- [Development](#development)

## Backend Boundary

A connector supplies a `Backend` implementation. For each authorized inbound
prompt, the shared runtime passes an `Invocation` containing the selected
working directory, optional prior session id, prompt, presentation-idle interval,
and total policy limit. The backend may emit only completed assistant text as `RunnerEvent::Text`
and returns privacy-safe `Outcome` metadata.

Connector crates are responsible for:

- defining their `ConfigSpec` and backend-specific environment variables;
- constructing the backend command safely;
- parsing the backend's documented machine-readable event stream;
- exposing only completed assistant output, never thinking or tool output;
- preserving or reporting the backend session id needed for the next prompt.

Each backend provides a typed `ProcessSpec`, selects its prompt transport, and
maps its strict decoder into the shared `ParsedEvent` vocabulary. The shared
runner owns spawning, bounded stderr, stdout and total deadlines, reply-channel
backpressure, first-session capture, and child termination and reaping.
A decoder that sees the backend drop or replace an attachment it was given
returns `ParsedEvent::AttachmentNotProcessed`. The runner then kills the
process group at once and fails the turn without keeping the session id
observed in that run. The backend may already have acted on the prompt before
the decoder reports the failure.

Claude Code, Codex, OpenCode, and Pi write prompt text to stdin. Backend-specific behavior
belongs in those connector crates, not in this shared runtime.

## Execution Profiles

`MARMOT_HARNESS_EXECUTION_PROFILE` expresses operator intent without pretending
the backends have equivalent permission or sandbox systems:

- `inherit` (default) adds no connector-owned execution-policy overrides.
- `autonomous` avoids interactive approvals while preserving configured hard
  denies and isolation where the backend supports them.
- `unrestricted` requests the backend's broadest non-interactive mode. It
  requires external isolation.

| Backend | `inherit` | `autonomous` | `unrestricted` | Built-in OS isolation |
| --- | --- | --- | --- | --- |
| Claude Code | Existing permission config | `--permission-mode acceptEdits`; explicit denies remain and other unanswered asks are denied | `--dangerously-skip-permissions` | None |
| Pi | Existing tool/config behavior | Same native approval-free invocation | Same native approval-free invocation | None |
| OpenCode | Existing permission config | `--auto`; explicit denies remain | `--auto` plus process-local `OPENCODE_CONFIG_CONTENT={"permission":"allow"}` | None |
| Codex | Existing approval, sandbox, and network config | `approval_policy="never"`; sandbox/network remain configured | `--dangerously-bypass-approvals-and-sandbox` | Configured for `inherit`/`autonomous`; bypassed for `unrestricted` |

The OpenCode overlay is set only on the spawned process and never rewrites the
operator's global or project configuration. The child does not inherit a
separate `OPENCODE_PERMISSION` override in this profile. Managed organization
policy is loaded later and may still override the process-local configuration.
Older backend versions that do not understand a required flag or
invocation-local config override fail the invocation; the harness does not fall
back to a broader or interactive mode and does not send a successful reply. Pi
needs no version-dependent permission flag because its normal non-interactive
mode is already approval-free.

Installers accept `--execution-profile inherit|autonomous|unrestricted` and
write the shared environment variable into the private env file and same-user
service configuration. Writing `unrestricted` requires the separate
`--acknowledge-unrestricted` flag, including in non-interactive and dry-run
installs.

### Security Boundary

An allowed Marmot sender combined with `unrestricted` execution is effectively
remote code execution as the harness service user. The `/<path>` picker chooses
a working directory; it is not an OS containment boundary. Run unrestricted
deployments as a dedicated OS user or inside a container/VM, and give that
boundary only narrowly scoped credentials. Backend logical permissions are not
equivalent to an OS sandbox.

Startup diagnostics report the selected profile and typed approval/isolation
support state alongside coarse fields such as the harness name, sender count,
and reply-size limit. They never include paths, identities, prompts,
configuration contents, or backend output.

## Shared Behavior

All connectors:

- speak `marmot.agent-control.v2` over a local Unix socket;
- require an explicit sender allowlist and mirror it additively into the
  account-scoped `wn-agent` welcomer allowlist;
- support only `always` activation today;
- use `/<path>` on the first group message to select a canonical working
  directory beneath `$HOME`;
- persist private per-group working-directory, session, and goal mappings;
- answer the reserved chat commands below before backend invocation;
- split durable replies on UTF-8 boundaries with a 30,000-byte default and a
  60,000-byte hard ceiling;
- report presentation-idle liveness as unknown without killing an invocation and
  enforce a separate total backend policy limit;
- persist typed recovery obligations and require an exact `/retry-last` or
  `/discard-last` command before uncertain or resumable work can leave its FIFO
  barrier;
- reconcile text-only final-delivery acknowledgements idempotently before later
  FIFO work, without replaying the backend invocation;
- preserve every inbound media reference in message order, download the complete batch through `wn-agent`, and expose one validated private staging copy per item at the backend boundary;
- keep short connect/write and ordinary control-response deadlines, but allow a media-download response at least sixteen minutes so the runtime's fifteen-minute acquisition can finish before the connector deadline;
- reject a complete attachment batch before backend invocation when any download, regular-file/ownership check, count limit, or aggregate-byte limit fails;
- give backends `attachment_preflight::revalidate`, which re-opens a staged copy without following symlinks immediately before spawn and fails the batch on a relative or non-UTF-8 path, a non-regular file, or a size change;
- remove batch copies after every terminal path and reconcile stale connector-owned batch directories on startup;
- bound every backend invocation's stdout framing, parsed output, and durable
  output requests with the per-turn [output limits](#output-limits);
- keep diagnostics free of identifiers, paths, prompts, attachment names, and backend output.

Backends that declare artifact support can also return completed files to the chat through `wn-agent`'s encrypted
`send_media` path. Exports are off by default and require `<PREFIX>_ARTIFACT_EXPORTS_ENABLED=true` plus at least one
exact group/export-root grant in `<PREFIX>_ARTIFACT_GRANTS_JSON`. Only `wn-codex` declares artifact support today; see
its [README](../codex/marmot/README.md).

Download timeouts, connector rejections, and local file-validation failures have
distinct privacy-safe pre-backend replies. The connector never forwards a
server-provided error string or attachment metadata into those replies.

### Output Limits

Each backend invocation gets finite output budgets. Connectors read them from
`<PREFIX>_<SUFFIX>`, where the prefix is `WN_CLAUDE`, `WN_CODEX`,
`WN_OPENCODE`, or `WN_PI`. Every value must be a decimal integer from 1 to its
hard maximum; zero, signs, malformed values, and values above the maximum are
rejected at startup without echoing the value.

| Suffix | Default | Hard maximum | Counts |
| --- | --- | --- | --- |
| `MAX_BACKEND_RECORD_BYTES` | 1 MiB | 4 MiB | Bytes in one stdout JSONL record, excluding the delimiter |
| `MAX_BACKEND_STDOUT_BYTES` | 16 MiB | 64 MiB | Raw stdout bytes, including delimiters and blank, ignored, or malformed records |
| `MAX_BACKEND_EVENTS` | 8192 | 65536 | Framed stdout records, charged before UTF-8 decoding or parsing |
| `MAX_ASSISTANT_TEXT_BYTES` | 1 MiB | 8 MiB | Parsed assistant-text bytes, including whitespace-only text |
| `MAX_ASSISTANT_TEXT_EVENTS` | 256 | 4096 | Parsed assistant-text events |
| `MAX_ARTIFACT_BUFFER_BYTES` | 512 KiB | 4 MiB | Assistant text retained as an artifact caption, including separators |
| `ARTIFACT_MAX_COUNT` | 10 | 10 | Declared artifacts summed across every artifact event in the turn |
| `MAX_REPLY_CHUNKS` | 64 | 256 | Reply chunks staged for the turn; a text, or a completed buffered batch, that would cross the cap stages none of its chunks |
| `MAX_DURABLE_SENDS` | 128 | 512 | Final, media, and activity requests for the turn, including every retry and status notice |

The stdout framer never buffers more than one record plus a fixed scratch
buffer, so an unterminated or oversized record is rejected before any of it is
parsed. The first breached limit wins: the connector stops the backend, drains
nothing further from it, and terminates its process group. A durable request
already waiting for acknowledgement is abandoned rather than awaited. Channel
backpressure between the runner and the delivery loop only delays the runner;
it never grows a buffer.

After a breach the turn sends nothing more: no buffered text, fallback text,
liveness or activity notice, artifact, or error reply. The turn is persisted as
limited behind an incomplete-final barrier, and any chunks staged but unsent
are withheld from reconciliation. When a backend session is known, the prompt
is kept as an uncertain-outcome recovery record because the backend may already
have acted; `/retry-last` reruns it and `/discard-last` clears it. Without a
session the barrier is discard-only. Either command releases the group's FIFO
lane; other groups are unaffected. A retry releases the earlier turn's pending
deliveries only after its own completion, including its final status notice,
stays within every limit; a retry that breaches a limit keeps both turns behind
the barrier until `/discard-last`.

A discard keeps its turns withheld and the group blocked until the turns'
pending artifact deliveries are durably removed. If that removal fails,
`/discard-last` reports the failure and nothing from those turns is sent,
including after a restart. Sending `/discard-last` again completes the discard.
Replay rechecks that each staged chunk or artifact delivery is still pending
before it is sent, so a discarded turn is never replayed on a fresh budget.

Durable send budgets survive restarts. Startup and periodic reconciliation
replay staged chunks only for turns that have finished, charge each replay
attempt against the same budget, and mark a turn limited instead of sending once
its budget is exhausted. Records written before budgets existed get a fresh
finite budget on first replay. Each admitted send attempt rewrites the private
delivery-state file before its request, so a turn performs at most
`MAX_DURABLE_SENDS` such writes.

If the connector stops or restarts while a turn is running, that turn's outcome
is unknown: the backend may have acted or breached a limit before the stop.
Startup therefore loads it as limited behind the same discardable barrier, and
its staged but unacknowledged chunks are not replayed. Other groups and turns
that had already finished are unaffected. Send `/discard-last` in that chat to
release it. Discarding does not clear a saved backend session.

While a chat waits on `/retry-last` or `/discard-last` for a limited or
interrupted turn, each newly queued message gets one activity notice naming the
available command, then stays queued until the barrier is released.

## Chat Commands

Terminal backends run through their non-interactive machine interfaces, which do
not expand the backend's own interactive slash commands. A message whose first
token is a reserved name below is therefore answered by the harness itself and
never reaches the backend:

| Command | Effect |
| --- | --- |
| `/help` | List these commands. |
| `/status` | Report backend name, workdir, session state, execution profile, and goal. |
| `/pwd` | Report the selected working directory as a `$HOME`-relative path. |
| `/cd <path>` | Select a working directory under `$HOME` and start a new session epoch. |
| `/new` | End the active backend session and keep the workdir. |
| `/reset-session` | Same as `/new`. |
| `/session-status` | Reserved for the active-turn status lane; until that lane is supported, return an unavailable reply without invoking the backend. |
| `/retry-last` | Retry the pending durable recovery record that blocks this chat. |
| `/discard-last` | Discard the recovery record and any incomplete, interrupted, or limited turn that blocks this chat, without replay. |
| `/goal <text>` | Store a standing instruction for this chat. `/goal` shows it; `/goal clear` removes it. |

A reserved name used with arguments it does not accept, such as
`/new right now`, returns a usage reply instead of being forwarded as a prompt.
Any other leading-slash message keeps the existing workdir-picker behavior, so
`/whitenoise fix the build` still selects `~/whitenoise` and prompts with the
rest. A directory whose name collides with a reserved command must be selected
with `/cd`.

Prefix a message with `//` to strip one slash and forward the rest verbatim
without command routing or workdir selection: `//status` sends the literal
`/status` to the backend. Backends differ in what they do with it. `codex exec`
and `opencode run` have no slash parsing at all, so the text is prompt prose. A
backend that does route slash commands in its non-interactive mode receives its
own command through this escape.

`/new` and `/reset-session` never delete backend-owned transcripts and never
retry a failed resumed prompt automatically; the next distinct prompt starts a
new logical backend session in the retained workdir. Reset application and its
acknowledgement outcome are durably keyed by the inbound message reference, so
any reconnect replay resends the same acknowledgement without advancing the
session epoch again. Observations from work started before that epoch boundary
cannot restore the old session.

On Unix, every backend invocation runs in its own process group. Timeout,
cancellation, an unprocessed attachment, and failure cleanup terminate the
whole group before reaping the direct child so backend-spawned descendants
cannot outlive an interrupted turn.
Normal and nonzero leader exits also terminate remaining group members before
reaping the leader. Exit observation retains the unreaped leader until this
cleanup completes, preventing PID reuse from redirecting a later group signal.
After leader exit, pipe draining has a separate two-second grace period so a
helper that escaped the group cannot stall the lane by retaining stdout/stderr.

The stored goal is prepended to every prompt in its chat as one delimited block.
That costs prompt tokens on every turn and, in exchange, survives session
resets, lost session ids, and backend context compaction. Goals are bounded to
4096 bytes and live only in the connector's private per-group state file.

`/retry-last` and `/discard-last` run ahead of queued prompts and are refused
while a turn is running. Retry requires a pending durable recovery record for
that group: it consumes the record once and reruns its prompt in the saved
session and workdir. A barrier without such a record, such as an incomplete,
interrupted, or limited turn with no known backend session, cannot be retried.
Discard removes the recovery record when one exists and also clears every
incomplete-final, interrupted, or limited-turn barrier in that group, with or
without a record or session. Nothing from a discarded turn is replayed, and the
discard is confirmed only after the turn's pending deliveries are durably
removed (see [output limits](#output-limits)). An uncertain outcome warns that
retrying may repeat side effects. Recovery state is stored in private files and
is never included in logs or diagnostics.

The connector READMEs document their environment variables, installer topology,
and backend contracts:

- [`integrations/claude/marmot/README.md`](../claude/marmot/README.md)
- [`integrations/codex/marmot/README.md`](../codex/marmot/README.md)
- [`integrations/opencode/marmot/README.md`](../opencode/marmot/README.md)
- [`integrations/pi/marmot/README.md`](../pi/marmot/README.md)

## Development

Run the shared suite and all connector suites after changing this crate:

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-claude
cargo test -p wn-codex
cargo test -p wn-opencode
cargo test -p wn-pi

just claude-dev-e2e-connector
just codex-dev-e2e-connector
just opencode-dev-e2e-connector
just pi-dev-e2e-connector

just claude-installer-test
just codex-installer-test
just opencode-installer-test
just pi-installer-test
```

The process-level connector tests are ignored by default and use real
`wn-agent` and connector binaries with fake backend executables. They do not
install or authenticate the real Claude Code, Codex, OpenCode, or Pi CLIs.
