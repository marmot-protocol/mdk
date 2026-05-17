# dm

`dm` is the command-line app for the Darkmatter/Marmot stack. It manages Nostr-keyed accounts, relay
lists, KeyPackages, chats, groups, messages, local projections, background sync, and the terminal UI.

The crate builds two binaries:

- `dm`: the user-facing CLI and TUI entrypoint.
- `dmd`: the background daemon used by `dm daemon start`.

`dm` uses `marmot-account` for account homes and secret storage, and `marmot-app` for the runtime bridge,
transport setup, group projection, message projection, and Nostr directory refresh.

The source directory is `crates/cli`. The Cargo package name remains `darkmatter-cli`, and the installed
commands remain `dm` and `dmd`.

## Install From This Checkout

Install both binaries into your local Cargo bin directory:

```sh
cargo install --path crates/cli --locked --bins
```

Make sure `~/.cargo/bin` is on `PATH`, then check the installed commands:

```sh
dm --help
dmd --help
```

For source-checkout work without installing:

```sh
cargo run -p darkmatter-cli --bin dm -- --help
cargo run -p darkmatter-cli --bin dmd -- --help
```

For isolated development runs, keep the home and secret store explicit:

```sh
export DM_HOME="$(mktemp -d)"
export DM_SECRET_STORE=file
```

The default secret store is the platform keychain. Use `DM_SECRET_STORE=file` only for local development,
tests, and disposable homes.

## Configuration

Common options can be passed as flags or environment variables:

- `--home <path>` or `DM_HOME`: account home, local relay files, projections, daemon socket, pid, and log.
- `--account <npub-or-hex>` or `DM_ACCOUNT`: selected local signing account for account-scoped commands.
- `--socket <path>` or `DM_SOCKET`: daemon socket. The default is `$DM_HOME/dev/dmd.sock`.
- `--secret-store keychain|file` or `DM_SECRET_STORE`: signing-key backend.
- `--keychain-service <name>` or `DM_KEYCHAIN_SERVICE`: keychain service name.
- `--relay <wss-url>`: use a Nostr relay through the SDK transport. Without this flag, `dm` uses the local
  file relay under the home directory.
- `--json`: return a stable JSON envelope for scripts, the TUI, and daemon forwarding.

The default home is `DM_HOME` when set. Without `DM_HOME`, `dm` uses the platform user data directory:

- macOS: `~/Library/Application Support/darkmatter`
- Linux and other non-macOS Unix: `$XDG_DATA_HOME/darkmatter`, or `~/.local/share/darkmatter`
- Windows: `%APPDATA%\darkmatter`

## Quick Start

Create two local signing accounts, publish Bob's KeyPackage, create a chat as Alice, and let Bob sync it:

```sh
export DM_HOME="$(mktemp -d)"
export DM_SECRET_STORE=file

dm account create
dm account create <bob-nsec>
dm account list

dm --account <bob-npub-or-hex> keys publish
dm --account <alice-npub-or-hex> group create general <bob-npub-or-hex>
dm --account <alice-npub-or-hex> message send <group-hex> "hello bob"

dm --account <bob-npub-or-hex> sync
dm --account <bob-npub-or-hex> chats list
dm --account <bob-npub-or-hex> message list --group <group-hex> --limit 20
```

Most account-scoped commands resolve the account in this order:

1. `--account <npub-or-hex>`
2. `DM_ACCOUNT`
3. the only local signing account, when exactly one exists

Public-only accounts can be added with `dm account create <npub-or-hex>`. They are useful for relay-list
and KeyPackage lookup, but cannot sign, publish KeyPackages, sync groups, or send messages.

## Command Map

Account commands:

```sh
dm account create [nsec-or-npub]
dm account list
dm account status [npub-or-hex]
dm account relay-lists [npub-or-hex] --bootstrap-relays <relay-url>
```

KeyPackage commands:

```sh
dm --account <npub-or-hex> keys publish
dm keys fetch <npub-or-hex> --bootstrap-relays <relay-url>
```

Chat projection commands:

```sh
dm --account <npub-or-hex> chats list
dm --account <npub-or-hex> chats list --include-archived
dm --account <npub-or-hex> chats show <group-hex>
dm --account <npub-or-hex> chats archive <group-hex>
dm --account <npub-or-hex> chats unarchive <group-hex>
```

Group commands:

```sh
dm --account <npub-or-hex> group create <name> [member-npub-or-hex ...]
dm --account <npub-or-hex> group members <group-hex>
dm --account <npub-or-hex> group invite <group-hex> <member-npub-or-hex> [...]
dm --account <npub-or-hex> group remove <group-hex> <member-npub-or-hex> [...]
dm --account <npub-or-hex> group update <group-hex> --name <name>
dm --account <npub-or-hex> group update <group-hex> --description <description>
```

Message commands:

```sh
dm --account <npub-or-hex> message send <group-hex> "hello"
dm --account <npub-or-hex> message send --group <group-hex> "--text that starts with a dash"
dm --account <npub-or-hex> message list
dm --account <npub-or-hex> message list --group <group-hex> --limit 20
```

Sync command:

```sh
dm --account <npub-or-hex> sync
```

## Daemon

`dm daemon start` launches `dmd` in the background for the selected home. The daemon owns the Unix socket,
writes `dev/dmd.pid`, appends startup errors to `dev/dmd.log`, and periodically syncs every local signing
account. It also refreshes the app-level Nostr user directory for local signing accounts, which warms cached
follow lists and profile metadata for likely contacts.

```sh
dm daemon start --sync-interval-ms 2000
dm daemon status
dm --account <npub-or-hex> chats list
dm daemon stop
```

When a daemon socket exists for a home, normal `dm --home <path> ...` commands are forwarded to that
daemon. `dm daemon status`, `dm daemon stop`, and `dm tui` handle daemon access directly.

Use `--socket` or `DM_SOCKET` to target a specific daemon. Use `dmd` directly when a process supervisor
should own the daemon lifecycle:

```sh
dmd --home "$DM_HOME" --sync-interval-ms 2000
```

## TUI

`dm tui` is a Ratatui interface over the real `dm --json` command surface. It lists local accounts, shows
visible chats for the selected local signing account, renders recent messages, and sends messages from a
composer.

```sh
dm tui
```

When a daemon is running for the same home, TUI child commands use the daemon socket. The header shows daemon
state. While the daemon is running, the TUI refreshes account, chat, and message projection data when the
composer is idle.

Controls:

- `Tab`: cycle accounts, chats, and composer.
- Arrow keys or `j`/`k`: move the selected account or chat.
- `Enter`: select the highlighted account/chat or submit the composer.
- `?`: open help.
- `Esc`: clear help or input.
- `Ctrl-C`: quit.

Composer slash commands:

```text
/sync
/refresh
/account <npub-or-hex>
/account create
/account add <npub-or-hex>
/account import <nsec>
/daemon status
/daemon start [sync-interval-ms]
/daemon stop
/chat new <name> [member-npub-or-hex ...]
/chat rename <name>
/chat describe <description>
/chat archive
/chat unarchive
/chat archived [on|off]
/members add <npub-or-hex> [...]
/members remove <npub-or-hex> [...]
/members list
/keys publish
/keys fetch <npub-or-hex>
/quit
```

`/account import <nsec>` redacts the secret in the composer. `/chat archived` shows archived chats so they
can be selected and unarchived; `/chat archived off` returns to the visible-chat list. Member commands operate
on the selected chat and call the same group membership commands exposed by the CLI.

## JSON Output

Pass `--json` for machine-readable output. Success responses wrap command data in a stable result envelope.
Errors use snake_case `error.code` values and include repair fields when the CLI can name the next command.

The TUI and daemon both depend on the JSON shape, so treat response changes as API changes.

## Changelog

Release notes for the CLI crate live in [`CHANGELOG.md`](CHANGELOG.md). Update it for user-facing CLI,
daemon, TUI, JSON, install, or packaging changes.

## Packaging Direction

Local development should keep using:

```sh
cargo install --path crates/cli --locked --bins
```

For public releases, Homebrew is the right first-class installer. Use the namespaced tap:

```sh
brew install marmot-protocol/tap/darkmatter
```

The tap formula lives in `github.com/marmot-protocol/homebrew-tap` and installs both `dm` and `dmd` from `crates/cli`.
Once release CI exists, the tap can publish bottles for macOS and Linux so users do not pay the full Rust build cost.
The project-side release checklist lives at `docs/release/dm-homebrew.md`.

While `marmot-protocol/darkmatter` is private, Homebrew source builds require GitHub access to the source repo. Public
tarball installs can replace that once the source repo is public or release assets are published somewhere installers can
download.

`cargo install --git ssh://git@github.com/marmot-protocol/darkmatter.git darkmatter-cli --locked --bins` is a useful
source install path for engineers and automation.

`cargo install darkmatter-cli` from crates.io is a later option. The workspace currently has
`publish = false`, and the CLI depends on local workspace crates. Publishing there needs a separate crate
publication plan or a split packaging crate.
