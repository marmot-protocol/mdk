# Marmot Terminal Harness

`marmot-terminal-harness` is the shared Rust runtime behind
[`wn-codex`](../codex/marmot), [`wn-opencode`](../opencode/marmot), and
[`wn-pi`](../pi/marmot). It keeps the
Marmot-facing behavior of pure terminal connectors consistent while leaving
backend command construction and event parsing in each connector crate.

The crate owns the `wn-agent` control client, account and sender selection,
inbound reconnect and resync, per-group bounded queues, deduplication, working
directory selection, private group-to-session mappings, reply chunking, and a
shared JSONL child-process runner. It does not own MLS, Nostr transport,
storage, QUIC previews, or backend-specific CLI semantics.

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

Codex, OpenCode, and Pi write prompt text to stdin. Backend-specific behavior
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
- keep diagnostics free of identifiers, paths, prompts, and backend output.

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
| `/retry-last` | Retry the durable recovery record that currently blocks this chat. |
| `/discard-last` | Discard the durable recovery record without replay. |
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
new logical backend session in the retained workdir.

The stored goal is prepended to every prompt in its chat as one delimited block.
That costs prompt tokens on every turn and, in exchange, survives session
resets, lost session ids, and backend context compaction. Goals are bounded to
4096 bytes and live only in the connector's private per-group state file.

`/retry-last` and `/discard-last` are available only while one matching durable
recovery record blocks that group. Retry consumes that record once and runs ahead
of queued prompts; discard removes it without replay. An uncertain outcome warns
that retrying may repeat side effects. Recovery state is stored in private files
and is never included in logs or diagnostics.

The connector READMEs document their environment variables, installer topology,
and backend contracts:

- [`integrations/codex/marmot/README.md`](../codex/marmot/README.md)
- [`integrations/opencode/marmot/README.md`](../opencode/marmot/README.md)
- [`integrations/pi/marmot/README.md`](../pi/marmot/README.md)

## Development

Run the shared suite and all connector suites after changing this crate:

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-codex
cargo test -p wn-opencode
cargo test -p wn-pi

just codex-dev-e2e-connector
just opencode-dev-e2e-connector
just pi-dev-e2e-connector

just codex-installer-test
just opencode-installer-test
just pi-installer-test
```

The process-level connector tests are ignored by default and use real
`wn-agent` and connector binaries with fake backend executables. They do not
install or authenticate the real Codex, OpenCode, or Pi CLIs.
