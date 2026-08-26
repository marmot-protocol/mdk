# AGENTS.md - terminal-harness

Shared control-plane runtime for Marmot terminal harnesses. Read `../AGENTS.md`
before changing this crate.

## Scope

- Own the `wn-agent` control client, inbound reconnect/resync loop, account and
  allowlist selection, per-group queues, deduplication, workdir picker, reserved
  chat commands, private session mapping, durable reply chunking, shared env
  configuration, process lifecycle plumbing, connector e2e support, and backend
  lifecycle boundary.
- Keep backend command construction and event parsing in each harness crate.
- Keep every reserved chat command in `src/commands.rs`. A reserved name must
  never fall through to the workdir picker, and a non-reserved leading-slash
  message must always stay a picker candidate. Adding a name is a documented
  breaking change for anyone whose `$HOME` holds a directory of that name.
- Keep per-group state changes on the targeted `SessionStore` mutators so a
  session, workdir, or goal write never silently discards a sibling field.
- Preserve privacy-safe diagnostics and never log identifiers, paths, prompts,
  model output, or transport data.
- Changes here must be verified against every terminal harness.

## Verification

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-codex
cargo test -p wn-opencode
cargo test -p wn-pi
```
