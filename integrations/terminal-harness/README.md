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

- [First installation and verification](#first-installation-and-verification)
- [Backend Boundary](#backend-boundary)
- [Execution Profiles](#execution-profiles)
- [Shared Behavior](#shared-behavior)
- [Chat Commands](#chat-commands)
- [Development](#development)

## First installation and verification

For admin promotion, task titles and progress reactions, see the
[recommended chat setup](../README.md#recommended-chat-setup). Every ordinary turn
provides the shared `wn-agent group-profile` route for admin name/description
updates. Verify the installed command, backend PATH and authorized socket access;
see [Admin group profile updates](#admin-group-profile-updates). Progress reactions
need a separately configured tool. The suggested instruction block is not
installed automatically.

Use the [checksum-verified quickstart](../README.md#get-started-white-noise--agents)
for the selected runtime. Claude Code, Codex, OpenCode and Pi share this setup
contract; their READMEs below describe backend-specific permissions and files.
The installer supplies `wn-agent` and the harness, not the model CLI, its login,
provider credentials or model configuration. Before installation, verify an
ordinary local model turn works as the same OS user that will run the service.
Do not change `HOME` to the connector directory: backend authentication and
project configuration remain owned by the native CLI.

### Record the two-process configuration

Every terminal connection needs a running `wn-agent` **and** one running
harness. Record its backend executable, connector home, socket, selected agent
account, allowed phone sender, relay set, service names and private session-map
path. Use the installer's `--help` and `--dry-run` to check that plan before
installing a matching release cohort. `wn-agent --version` and `wn-<runtime> --version` alone do not prove the backend is authenticated or receiving prompts.

The installer accepts public npub or hex values for `--allow-welcomer` /
`--allow-sender`. A fresh installation uses the normalized list for both invite
admission and prompt authorization. An existing `<PREFIX>_ALLOWED_SENDERS_HEX`
can retain a separate prompt-sender list, so verify the final service/env values
rather than assuming a newly allowed inviter can invoke the backend. The harness mirrors its sender list
**additively** into the account's invite allowlist. Removing invite permission
alone is not prompt revocation: update the harness sender list and restart it,
and remove the invite entry too when that should be revoked.

The default homes/services differ by runtime. For a second instance of the
**same** harness, make its home, socket, bootstrap label, agent service,
harness service and launchd labels distinct. Changing only `--home` does not
change a service name or the default session-map path. Set a separate
`WN_CLAUDE_STATE_PATH`, `WN_CODEX_STATE_PATH`, `WN_OPENCODE_STATE_PATH` or
`WN_PI_STATE_PATH` for same-kind instances; Pi's backend session directory also
needs its own `WN_PI_SESSION_DIR` when explicitly overridden. Persist these
settings in the actual service/launcher, not just the install shell.

For intentional sharing, one daemon/service owns the shared socket, each harness
selects its account explicitly, and only trusted consumers share the control
boundary. A prompt allowlist is not an account-scoped control-token boundary.
Several eligible subscribers to the same account/group can all respond.

### Manual startup and service environments

A foreground `wn-agent` occupies its terminal. Bootstrap and the harness belong
in a **second terminal** with the same home/socket/relay/auth settings. Never
start a second daemon beside an already-installed service to complete bootstrap.
Without a service manager, supervise both processes explicitly. `--no-service`
means services are not installed, not that bootstrap cannot start a temporary
daemon; the installer cleans that temporary process up when it exits.
`--no-start-wn-agent` also leaves the harness stopped; `--no-start-wn-<runtime>`
leaves that harness stopped. Follow the printed manual-start instructions.

The release installer writes `$MARMOT_HOME/dev/wn-<runtime>.env`. For a manual
harness start, load the **trusted, installer-generated** file in Bash and export
its assignments to the child:

```bash
# Replace the home and filename with this installation's recorded values.
export MARMOT_HOME="$HOME/.marmot-agents/codex"
set -a
. "$MARMOT_HOME/dev/wn-codex.env"
set +a
wn-codex
```

Do not run this beside an active `wn-codex` service. The file is a Bash-sourceable
manual-start aid, not a provider-credential export. Generated systemd/launchd
services embed their own environment; editing this file or exporting a variable
in a terminal does **not** update a running service. Apply approved overrides
through the service manager and restart only the corresponding service. Keep
provider login and tokens private; do not paste them into White Noise.

### Prove the first model reply

1. Check that the two intended services are running, the socket is reachable,
   and the configured account matches the bootstrap agent npub. Verify the
   backend executable and native authentication under the service user.
2. Invite that agent from the authorized phone account over the configured
   public relays. The phone's public npub identifies the sender to allow; it is
   not a secret identity to import as the agent.
3. Send `/help`, then select a trusted directory under the service user's `HOME`
   with `/<path>` or `/cd <path>` and confirm `/pwd` / `/status`. These are local
   harness commands, not proof that a model ran. Codex needs a Git repository
   by default; the other backends retain their own project rules.
4. Send an ordinary text prompt and verify an actual model reply in the same
   White Noise conversation. Only then report the round trip verified. If phone
   testing is unavailable, keep local installation checks and phone verification
   separate. Do not loosen permissions or sender policy to hide a failure.

### Know the file capability before testing it

| Harness | Inbound files | Generated-file return |
| --- | --- | --- |
| Claude Code | Non-empty file batches are rejected before invocation | Not implemented |
| Codex | Recognized images and the documented staged-file classes | Opt-in completion manifest with an exact group/export-root grant |
| OpenCode | Its documented text/image/PDF classifications | Not implemented |
| Pi | Its documented image or nonempty NUL-free UTF-8 classifications | Not implemented |

See the exact [Codex](../codex/marmot/README.md#inbound-attachments),
[OpenCode](../opencode/marmot/README.md#inbound-attachments) and
[Pi](../pi/marmot/README.md#attachments) file matrices and Claude Code's
[security notes](../claude/marmot/README.md#security-notes). A local path is not
proof the model received or understood a file. Unsupported mixed batches fail
as a unit; the harness does not silently drop an attachment and run the text.
`MEDIA:` is Hermes syntax, not an export command for these terminal harnesses.
For Codex exports, the selected backend must be able to write both the authorized
export files and its completion manifest under its existing execution policy.
The harness's source grant and `wn-agent --media-allowed-root` staging permission
are separate and both must be configured; do not widen either to the whole home.

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
- keep diagnostics free of identifiers, paths, prompts, attachment names, and backend output.

Backends that declare artifact support can also return completed files to the chat through `wn-agent`'s encrypted
`send_media` path. Exports are off by default and require `<PREFIX>_ARTIFACT_EXPORTS_ENABLED=true` plus at least one
exact group/export-root grant in `<PREFIX>_ARTIFACT_GRANTS_JSON`. Only `wn-codex` declares artifact support today; see
its [README](../codex/marmot/README.md).

Download timeouts, connector rejections, and local file-validation failures have
distinct privacy-safe pre-backend replies. The connector never forwards a
server-provided error string or attachment metadata into those replies.

## Admin group profile updates

Codex, Claude Code, OpenCode and Pi receive the same connector-provided control
instructions on each ordinary turn, including resumed turns. Literal `//`
forwarding omits this suffix, including after durable recovery and `/retry-last`.
Old recovery records without a forwarding discriminator retain ordinary-turn
behavior. When the user asks the
agent to change this conversation's name or description, it can invoke the
`wn-agent` binary from the same release bundle with a JSON object on stdin:

```sh
printf '%s' '{"name":"New name","description":"New description"}' | wn-agent group-profile
```

Omit a field to preserve it; an empty string explicitly clears it. Names are
limited to 256 UTF-8 bytes and descriptions to 4096 bytes. The shared runtime
supplies `MARMOT_AGENT_SOCKET`, `MARMOT_ACCOUNT_ID_HEX`, `MARMOT_GROUP_ID_HEX`,
authentication and the request timeout only in that turn's child process.
Parallel conversations never change global environment state. The agent should
use this route as supplied, rather than guess an account or group.

The command uses the existing authenticated `group_profile_update` operation.
MDK checks current admin authority when committing; `not_group_admin` is a
rejection. A successful response contains `ok: true` and the commit message ids.
A timeout, EOF or invalid acknowledgement is reported as an unknown outcome:
the update may have committed, so inspect current group details before retrying.
The command does not retry a mutation automatically.

Use a matching `wn-agent` and harness release containing this command and keep
`wn-agent` on the backend's PATH. Backend shell permissions and sandbox policy
remain authoritative; the harness does not override a policy denying socket
access. The local token still grants the existing full control API; the turn
route is convenience context, not a new per-group security capability. Use an
isolated connector home for a separate trust boundary.

A configured token, including one loaded from a token file, is passed as the raw
`MARMOT_AGENT_AUTH_TOKEN` value to each backend child. Tool shells, MCP servers
and other descendants that inherit its environment can use the full control
API for every account in that connector home. Only run trusted descendants in
that boundary. Backend environment filtering must explicitly preserve the
turn's `MARMOT_*` route and token for `wn-agent group-profile`; permission to
launch a shell alone does not ensure that these values reach it. Without a turn
token, the CLI retains its normal connector-home `control.token` fallback.

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

`/retry-last` and `/discard-last` are available only while one matching durable
recovery record blocks that group. Retry consumes that record once and runs ahead
of queued prompts; discard removes it without replay. An uncertain outcome warns
that retrying may repeat side effects. Recovery state is stored in private files
and is never included in logs or diagnostics.

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
