# AGENTS.md - Prime Agent Marmot Connector

Scope: `integrations/prime-agent/marmot`.

Read `../../terminal-harness/AGENTS.md` and this crate's `README.md` before changing connector behavior.

## Boundary

- Keep the Marmot control, allowlist, queue, reply, preview, and session-store behavior in `marmot-terminal-harness`.
- Keep Prime Agent daemon protocol v7 framing, session lifecycle, model commands, and attachment conversion in this crate.
- Do not add a Node/TypeScript runtime client dependency; speak the documented NDJSON Unix-socket protocol directly.
- Treat Prime Agent protocol changes as compatibility changes. Update the fake daemon contract test and the ignored live smoke test together.
- The `create` command's stable session name is a top-level field; runtime options such as `cwd` belong under `config`.

## Safety

- Keep the daemon socket under the private connector home by default.
- Never trace account ids, group ids, message ids, session ids/names, paths, prompts, assistant output, tool payloads, model credentials, or file contents.
- Forward only append-only assistant text as an ephemeral preview and only final assistant text as durable Marmot output.
- Keep one serialized prompt queue per group. Do not silently change queued prompts into daemon steering messages.
- `/model provider/model` is a control command: validate it against available models, do not submit it as prompt text, and return a bounded confirmation/error.

## Verification

```sh
cargo test -p wn-prime-agent --all-targets
just prime-agent-dev-e2e-connector
just prime-agent-installer-test
just fast-ci
```

The live daemon smoke test requires explicit `WN_PRIME_AGENT_LIVE_SMOKE=1`; see the README. Keep Prime Agent 0.7.0 pinned in installer coverage until protocol compatibility with another release is deliberately verified.
