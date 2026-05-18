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
- Keep one spelling per product capability: `keys`, `chats`, top-level `--account <npub-or-hex>`, and positional
  basics for common group and message flows. Do not add hidden compatibility aliases for old command shapes.
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

- `account`: create/import public or local signing accounts, list accounts, inspect status, and inspect relay lists.
- `keys`: publish the selected local account's KeyPackage and fetch another account's latest KeyPackage.
- `chats`: list, show, archive, and unarchive local chat projections.
- `group`: create groups, list members, invite/remove members, and update profile fields.
- `message`: send text messages and list projected messages.
- `stream`: receive and send provisional QUIC agent text stream previews.
- `sync`: process relay events for the selected local signing account.
- `daemon`: start, stop, and inspect `dmd`.
- `tui`: open the Ratatui interface over the real `dm --json` command surface.

## Daemon Guidance

- Keep `dm daemon start|stop|status`, the `dmd` binary, socket-backed execution, pid/log files, and background sync
  covered when touched.
- `dm daemon start` should spawn `dmd` with the selected home, socket, relay, secret store, keychain service, and sync
  interval.
- Normal commands may forward to `dmd` when a socket exists for the selected home. Daemon control commands and TUI
  startup handle daemon access directly.
- Background sync should refresh local signing accounts and the app-level Nostr user directory.
- Keep daemon status JSON useful for the TUI: running state, pid, socket, interval, log path, and last sync summary.

## TUI Guidance

- Keep `dm tui` as a Ratatui shell over `dm --json`. It should add navigation and slash commands without becoming a
  second app runtime.
- Keep account onboarding on top of `dm account create`; redact `nsec` import input before rendering it in the composer.
- Keep daemon controls on top of `dm daemon start|stop|status`; live refresh should observe daemon state and avoid
  interrupting active composer input.
- Keep chat and group management on top of real CLI commands. `/chat new` is the TUI spelling for chat creation; do not
  reintroduce `/new` as a hidden compatibility alias.
- Keep member commands direct: `/members add`, `/members remove`, and `/members list` operate on the selected chat.
  Do not add a hidden in-memory member draft or a `/members clear` command.
- Do not fake image messages in the TUI by sending file paths, plaintext placeholders, or raw bytes through
  `message send`. Add an image command only when it uses the real encrypted-media/blob upload path.

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
