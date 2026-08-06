# Marmot Terminal Harness

`marmot-terminal-harness` is the shared Rust runtime behind
[`wn-opencode`](../opencode/marmot), [`wn-pi`](../pi/marmot), and
[`wn-prime-agent`](../prime-agent/marmot). It keeps the
Marmot-facing behavior of pure terminal connectors consistent while leaving
backend command construction and event parsing in each connector crate.

The crate owns the `wn-agent` control client, account and sender selection,
inbound reconnect and resync, per-group bounded queues, deduplication, working
directory selection, private group-to-session mappings, reply chunking,
optional QUIC preview/final lifecycle, and backend process lifecycle helpers.
It does not own MLS, Nostr transport, storage, the QUIC transport
implementation, or backend-specific CLI semantics.

## Backend Boundary

A connector supplies a `Backend` implementation. For each authorized inbound
prompt, the shared runtime passes an `Invocation` containing the selected
working directory, optional prior session id and durable session file, stable
session name, prompt, backend-supported attachments, idle timeout, and total
timeout. The backend may emit append-only assistant text deltas as
`RunnerEvent::Preview`, followed by completed assistant text as
`RunnerEvent::Text`, and returns privacy-safe `Outcome` metadata.

Connector crates are responsible for:

- defining their `ConfigSpec` and backend-specific environment variables;
- constructing the backend command safely;
- parsing the backend's documented machine-readable event stream;
- exposing only completed assistant output, never thinking or tool output;
- preserving or reporting the backend session id needed for the next prompt.

OpenCode keeps prompt text after its command's `--` delimiter. Pi writes prompt
text to stdin. Prime Agent speaks daemon protocol v7 over a Unix socket and is
the only current terminal backend that opts into attachment downloads.
Backend-specific behavior belongs in those connector crates, not in this shared runtime.

## Shared Behavior

All connectors:

- speak `marmot.agent-control.v2` over a local Unix socket;
- require an explicit sender allowlist and mirror it additively into the
  account-scoped `wn-agent` welcomer allowlist;
- support only `always` activation today;
- use `/<path>` on the first group message to select a canonical working
  directory beneath `$HOME`;
- persist private per-group working-directory and session mappings;
- split durable replies on UTF-8 boundaries with a 30,000-byte default and a
  60,000-byte hard ceiling;
- enforce bounded per-group queues plus idle and total backend timeouts;
- keep diagnostics free of identifiers, paths, prompts, and backend output.

The connector READMEs document their environment variables, installer topology,
and backend contracts:

- [`integrations/opencode/marmot/README.md`](../opencode/marmot/README.md)
- [`integrations/pi/marmot/README.md`](../pi/marmot/README.md)
- [`integrations/prime-agent/marmot/README.md`](../prime-agent/marmot/README.md)

## Development

Run the shared suite and all connector suites after changing this crate:

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-opencode
cargo test -p wn-pi
cargo test -p wn-prime-agent

just opencode-dev-e2e-connector
just pi-dev-e2e-connector
just prime-agent-dev-e2e-connector

just opencode-installer-test
just pi-installer-test
just prime-agent-installer-test
```

The OpenCode and Pi process-level connector tests are ignored by default. The
Prime Agent restart regression runs in the default package test suite. All
three use real `wn-agent` and connector binaries with fake backend executables;
they do not install or authenticate the real OpenCode, Pi, or Prime Agent CLIs.
