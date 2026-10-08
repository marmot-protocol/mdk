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
- Keep `/new` durable and replay-safe: bind every applied reset result to the
  inbound message reference, advance a monotonic session generation once per
  distinct command, and reject backend observations from older generations.
- On Unix, spawn each backend in a dedicated process group and preserve the
  cancellation guard that kills the group before the direct child is reaped.
- Preserve privacy-safe diagnostics and never log identifiers, paths, prompts,
  model output, or transport data.
- Keep artifact export opt-in and grant-scoped: disabled unless
  `<PREFIX>_ARTIFACT_EXPORTS_ENABLED` is set and at least one exact group/root
  grant is configured. Only backends that declare `ArtifactSupport` may export.
- Changes here must be verified against every terminal harness.

## Key Files

- `src/lib.rs` - public types (`Backend`, `Invocation`, `Outcome`, limits) and
  re-exports.
- `src/bridge.rs` - `run` entrypoint, inbound loop, per-group lanes, recovery
  barriers, media staging, and reply delivery.
- `src/control.rs` - `wn-agent` control-socket client.
- `src/config.rs` - shared `ConfigSpec` env loading and defaults.
- `src/commands.rs` - reserved chat commands.
- `src/repo_picker.rs` - `/<path>` workdir selection under `$HOME`.
- `src/store.rs` - private per-group session/workdir/goal/recovery state.
- `src/process.rs` - JSONL child-process runner and process-group cleanup.
- `src/chunking.rs` - UTF-8-safe reply chunking.
- `src/error.rs` - `HarnessError` and privacy-safe error text.
- `src/artifacts.rs` - opt-in artifact export grants, staging, and manifests.
- `src/test_support.rs` - connector e2e helpers (`test-support` feature, Unix).
- `tests/jsonl_process.rs` - process-runner integration tests.
- `tests/test_installer.sh` - shared installer suite driven by each harness's
  `tests/test_installer.sh`.

For user-facing behavior (execution profiles, chat commands, shared behavior)
see `README.md`.

## Verification

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-claude
cargo test -p wn-codex
cargo test -p wn-opencode
cargo test -p wn-pi
cargo test -p wn-goose
just claude-dev-e2e-connector
just codex-dev-e2e-connector
just opencode-dev-e2e-connector
just pi-dev-e2e-connector
just goose-dev-e2e-connector
```

Run the matching `just <harness>-installer-test` recipes when changing installer
behavior or `tests/test_installer.sh`.
