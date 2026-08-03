# AGENTS.md - terminal-harness

Shared control-plane runtime for Marmot terminal harnesses. Read `../AGENTS.md`
before changing this crate.

## Scope

- Own the `wn-agent` control client, inbound reconnect/resync loop, account and
  allowlist selection, per-group queues, deduplication, workdir picker, private
  session mapping, durable reply chunking, shared env configuration, process
  lifecycle plumbing, connector e2e support, and backend lifecycle boundary.
- Keep backend command construction and event parsing in each harness crate.
- Preserve privacy-safe diagnostics and never log identifiers, paths, prompts,
  model output, or transport data.
- Changes here must be verified against every terminal harness.

## Verification

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-opencode
cargo test -p wn-pi
```
