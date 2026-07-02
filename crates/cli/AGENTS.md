# AGENTS.md - cli

Command-line app, background daemon, and terminal UI for the Darkmatter/Marmot stack.

## Scope

- Keep `dm` product-facing. Do not add smoke-test-only commands here.
- Keep `dm`, `dmd`, and `dm tui` on the real account/session/transport path through `marmot-account` and
  `marmot-app`.
- Use relay-backed test support for local coverage. Prefer `nostr-relay-builder::MockRelay` in crate tests and Docker
  local relays for true CLI/daemon end-to-end checks.
- Keep Nostr public keys as the CLI identity layer. Do not introduce user-label account selection in product
  commands.
- Do not add a CLI address-book or user-directory browsing namespace unless the product direction changes. Pubkeys are
  passed directly to group, member, and key commands; directory warming lives under `marmot-app` and daemon behavior.
- Prefer the Whitenoise-shaped product surface: `create-identity`, `login`, `logout`, `whoami`, `accounts`, `keys`,
  `chats`, `groups`, `messages`, `follows`, `profile`, `relays`, `settings`, `users`, top-level
  `--account <npub-or-hex>`, and positional basics for common group and message flows. Keep older singular `account`,
  `group`, and `message` commands working during the transition. If the Whitenoise-shaped command has no real
  Darkmatter behavior yet, return an explicit `unsupported_command` JSON error instead of faking success.
- Keep command output useful for humans by default and stable JSON when `--json` is passed.
- Treat JSON response shapes as TUI, daemon, and script inputs. Change them deliberately.
- Keep the README user-facing and current. Prefer installed `dm` examples; use `cargo run -p darkmatter-cli --bin dm`
  only when documenting source-checkout work.
- Keep `CHANGELOG.md` current for user-facing CLI, daemon, TUI, JSON, install, or packaging changes. Use the
  `Unreleased` section until a version is tagged.
- Keep local development installable with `cargo install --path crates/cli --locked --bins`.
- Treat the namespaced Homebrew tap `marmot-protocol/tap` as the preferred public packaging path unless product
  direction changes. The formula should install both `dm` and `dmd`; crates.io install needs a separate publish plan
  because the workspace currently has `publish = false`.
- Do not print or log nsecs, secret key hex, plaintext database keys, or other key material.

## Command Surface

- `create-identity`, `login`, `logout`, `whoami`, `account`, and `accounts`: create/import/remove public or local
  signing accounts, list accounts, inspect status, and inspect relay lists. `export-nsec` is present but must not print
  private key material.
- `keys`: list/publish/check the selected local account's KeyPackage, force-mint a replacement with `keys rotate`
  (alias `force-publish`), and fetch another account's latest KeyPackage.
- `chats`: list, list-archived, show, subscribe, subscribe-archived, archive, and unarchive local chat projections.
- `group` and `groups`: create groups, list/show groups, list members/admins/relays, invite/add/remove members, update
  profile fields, and subscribe to runtime-owned group-state updates through the daemon.
- `messages`: send text messages, list/search projected messages with Whitenoise-shaped cursor flags, subscribe to
  runtime-owned typed message updates through the daemon, and the `timeline` subgroup (list/search/subscribe over the
  materialized message timeline).
- `follows`, `profile`, `relays`, `settings`, and `users`: expose the current Nostr directory/settings behavior.
- Reaction, delete, retry, encrypted media, and admin/member management commands have implemented CLI behavior; keep
  their JSON shapes aligned with the `Unreleased` changelog entries when changing them.
- `notifications` and user-driven invite accept/decline commands: keep the Whitenoise-shaped command names but return
  `unsupported_command` until real behavior exists.
- `stream`: anchor, watch, receive, send, finish, and verify provisional QUIC agent text stream previews.
- `sync`: diagnostic catch-up for processing relay events for the selected local signing account.
- `relay-stats`: print device-local relay performance telemetry (aggregate counters, cross-relay spread, per-relay
  first-deliverer and first-event/EOSE timing, redacted relay health). Reads the live `dmd` runtime when a socket
  exists. Aggregate-only; per-relay rows use opaque device-local indices, never relay URLs.
- `daemon`: start, stop, and inspect `dmd`.
- `tui`: open the Ratatui interface over the real `dm --json` command surface.

## Daemon Guidance

- Keep `dm daemon start|stop|status`, the `dmd` binary, socket-backed execution, pid/log files, runtime subscription
  workers, and diagnostic catch-up covered when touched.
- `dm daemon start` should spawn `dmd` with the selected home, socket, secret store, keychain service, and
  daemon-configured relay defaults. Keep `dm daemon start` and direct `dmd` setup flags aligned with `wnd`, including
  `--data-dir`, `--logs-dir`, `--discovery-relays`, and `--default-account-relays`.
- Normal commands may forward to `dmd` when a socket exists for the selected home. Daemon control commands and TUI
  startup handle daemon access directly.
- Runtime subscriptions should keep local signing accounts current; explicit catch-up remains a diagnostic/repair path.
- Keep daemon status JSON useful for the TUI: running state, pid, socket, log path, last runtime activity summary,
  relay health, and background stream watch summaries.
- Keep QUIC preview subscription output under `messages subscribe` as typed `stream_preview` updates. Do not introduce
  user-facing `streams subscribe` or `stream subscribe` commands for the same app-level feed.
- Keep daemon streaming output newline-delimited and typed. Current user-facing subscription feeds are
  `messages subscribe`, `messages timeline subscribe`, `chats subscribe`, `chats subscribe-archived`, and
  `groups subscribe-state`.

## TUI Guidance

- Keep `dm tui` as a Ratatui shell over `dm --json`. It should add navigation and slash commands without becoming a
  second app runtime.
- Keep account onboarding on top of `dm create-identity` and `dm login`; redact `nsec` import input before rendering it in the composer.
- Keep daemon controls on top of `dm daemon start|stop|status`; live refresh should observe daemon state and avoid
  interrupting active composer input.
- Keep TUI stream controls on top of the real `dm stream` commands. Broker watches should use runtime-tracked daemon
  watches instead of blocking the TUI event loop.
- Keep chat and group management on top of real CLI commands. `/chat new` is the TUI spelling for chat creation; do not
  reintroduce `/new` as a hidden compatibility alias.
- Keep member commands direct: `/members add`, `/members remove`, and `/members list` operate on the selected chat.
  Do not add a hidden in-memory member draft or a `/members clear` command.
- Do not fake image messages in the TUI by sending file paths, plaintext placeholders, or raw bytes through
  `message send`. Add an image command only when it uses the real encrypted-media/blob upload path.

## Key files

- `src/lib.rs`: crate entrypoint and wiring. Owns `run_from`/`run_cli_local`, the `execute`/`execute_inner` command
  dispatch (which calls `commands::<namespace>::<handler>`), the daemon-socket routing/fallback glue, `CliOutput` /
  `CommandOutput` / `CliRuntimeInfo` types, and the broadly-shared `pub(crate)` helpers (`resolve_account`,
  `npub_for_account_id`, `ensure_local_signing`, `normalize_group_id_hex`, `relay_endpoints`, `validate_relay_url`,
  `group_json`/`group_show_output`, `agent_text_stream_payload_value`, `unsupported_command`, home/secret-store
  resolution, etc.).
- `src/commands/`: per-namespace command handlers, each module mirroring a `*Command` enum in `args.rs`. The
  `foo_command` / `foo_command_with_runtime` pairs plus the output/format helpers used only by that namespace live
  here. Modules: `account` (create-identity/login/whoami/account(s) + account-setup output), `key_package` (keys),
  `chats`, `media`, `groups` (group + groups), `messages` (incl. the `timeline` subgroup), `follows`, `profile`,
  `relays`, `settings`, `users`, `notifications`, `stream` (QUIC agent text stream previews + quic-candidate/trust
  helpers), `debug`, `sync`, and `relay_stats`. Handlers and helpers reached from the lib dispatch, from the `daemon`
  module, or across namespaces are `pub(crate)`.
- `src/args.rs`: clap argument/command enums (`Cli`, `Command`, and the per-namespace `*Command` types).
- `src/error.rs`: `DmError` and the `--json` error rendering.
- `src/daemon/`: `dmd` runtime, socket-backed execution, subscription workers; calls
  `commands::<namespace>::*_with_runtime` handlers and shared `commands::stream` / `commands::account` helpers.
  `mod.rs` keeps the accept loop / request dispatch (`run_server`, `handle_connection`) and re-exports the
  submodules: `protocol` (request/response wire types, framing, `DaemonClient`), `responses` (stream-response
  construction + subscription matching), `subscriptions` (the streaming `handle_*_subscription` handlers),
  `stream_workers` (background stream-watch and stream-compose workers), `runtime_host` (app-runtime reconciliation,
  event bridge, hosted command dispatch), and `lifecycle` (start/stop/status, pid/log/socket files). `tests.rs`
  holds the daemon unit tests.
- `src/tui/`: Ratatui shell over the `dm --json` surface. `mod.rs` keeps the `run_tui` entry plus shared constants
  and re-exports the submodules: `model` (row/view/state types, JSON parsers, pure helpers), `view` (`TuiApp` draw
  methods + Ratatui line/style helpers), `slash` (slash-command parsing), `client` (`DmClient` subprocess wrapper,
  subscription readers, and the `dm`/subscription-driving `TuiApp` methods), and `app` (`TuiApp` state plus the
  event loop, key handling, and selection methods). `tests.rs` holds the TUI unit tests.
- `tests/cli.rs`: end-to-end CLI/daemon integration tests asserting real `dm`/`dmd` behavior and JSON shapes.

## Verification

For docs-only changes, run the help commands that cover the documented surface:

```sh
cargo run -p darkmatter-cli --bin dm -- --help
cargo run -p darkmatter-cli --bin dmd -- --help
```

For behavior changes, start with the focused crate tests:

```sh
cargo test -p darkmatter-cli
cargo test -p marmot-app
```

Then widen before checkpointing cross-crate changes:

```sh
just fmt-check
just check
just clippy
just test
```
