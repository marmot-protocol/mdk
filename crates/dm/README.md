# dm

`dm` is the first real app surface for the Darkmatter/Marmot stack.

It is intentionally small, but it is not a smoke harness: commands are named around accounts, keys, chats, groups,
messages, and sync. Pass `--json` for a stable response envelope; `dm tui` uses that same surface.

The CLI uses `marmot-account` for account home/key storage and `marmot-app` for the runtime bridge plus Nostr
account-relay setup. `dm` can run commands directly or send them to the background `dmd` daemon over a Unix socket.

## Examples

Nostr is the identity layer. Local signing accounts are generated with `account create` or imported with
`account create <nsec>`. Public accounts can be added with `account create <npub-or-pubkey-hex>`, but they cannot sign,
publish KeyPackages, sync, or send messages.

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file account create
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file account create <bob-nsec>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <bob-npub-or-hex> keys publish
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <alice-npub-or-hex> group create general <bob-npub-or-hex>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <bob-npub-or-hex> sync
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <alice-npub-or-hex> message send <group-hex> "hello bob"
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <bob-npub-or-hex> sync
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <bob-npub-or-hex> chats list
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account <bob-npub-or-hex> message list --group <group-hex> --limit 20
```

## TUI

`dm tui` is a Ratatui shell over the real CLI. It lists local accounts, shows visible chats for the selected local
signing account, renders recent messages, and sends messages from a composer. When a daemon socket exists for the same
home, the TUI's child `dm --json` commands use the daemon just like normal CLI commands. The header shows daemon state,
and while the daemon is running the TUI periodically refreshes the visible account/chat/message projection when the
composer is idle.

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file tui
```

Controls stay deliberately small:

- `Tab` cycles accounts, chats, and composer.
- Arrow keys move the selected account or chat.
- `Enter` selects the highlighted account/chat or submits the composer.
- `?` opens help, `Esc` clears help/input, and `Ctrl-C` quits.

The composer accepts either a plain chat message or a slash command:

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
/new <name> [member-npub-or-hex ...]
/invite <npub-or-hex>
/remove <npub-or-hex>
/keys publish
/keys fetch <npub-or-hex>
/quit
```

`/account create` generates a local signing account, `/account import <nsec>` imports a local signing account, and
`/account add <npub-or-hex>` adds a public-only account for relay-list and KeyPackage lookup. Imported `nsec` input is
redacted in the composer.

Most account-scoped commands resolve the local account in this order:

1. top-level `--account <npub-or-hex>`, before the command
2. `DM_ACCOUNT`
3. the only local account, when exactly one exists

Use `keys` for normal KeyPackage work:

```sh
dm --account <npub-or-hex> keys publish
dm --account <npub-or-hex> keys fetch
dm keys fetch <npub-or-hex> --bootstrap-relays <relay-url>
```

There are no legacy aliases for this namespace; `keys` is the command.

Daemon commands:

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file daemon start --sync-interval-ms 2000
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm daemon status
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm daemon stop
```

Once a daemon socket exists for a home, `dm --home <path> ...` will send normal commands to `dmd`. The daemon writes
`dev/dmd.pid`, appends startup errors to `dev/dmd.log`, and periodically syncs every local signing account. Use
`--socket` or `DM_SOCKET` to target a specific daemon.

During account setup and background sync, `dm`/`dmd` also lets `marmot-app` refresh the Nostr user directory for local
signing accounts. That warms cached follow lists and profile metadata for likely contacts without adding a CLI address
book. Product commands still take `npub` or hex pubkeys directly at the point of use.

Two-terminal local loop:

Terminal 1:

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file daemon start --sync-interval-ms 1000
```

Terminal 2:

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm account create
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm account create <bob-nsec>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --account <bob-npub-or-hex> keys publish
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --account <alice-npub-or-hex> group create general <bob-npub-or-hex>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --account <bob-npub-or-hex> chats list
```

Chat commands are the preferred user-facing spelling for local chat projection work:

```sh
dm --account <npub-or-hex> chats list
dm --account <npub-or-hex> chats show <group-hex>
dm --account <npub-or-hex> chats archive <group-hex>
dm --account <npub-or-hex> chats unarchive <group-hex>
```

When an account is removed from a group, `dm` keeps that account's local group and message projection as history.
Archiving or hiding that group is a separate user decision, not an automatic side effect of membership removal.

`--json` errors use stable snake_case `error.code` values and include repair fields when the CLI can name a concrete
next command.

`account status` is the quickest operator view. It reports relay-list completeness, group/message/event counts, the
selected secret-store backend, and whether the per-account projection database exists and is encrypted.

`dm` uses the platform keychain/credential store for account signing keys by default. Pass `--secret-store file`, or set
`DM_SECRET_STORE=file`, for isolated deterministic development runs. The keychain service defaults to
`com.marmot.darkmatter`; use `--keychain-service` or `DM_KEYCHAIN_SERVICE` to override it for host apps and test
installations.

The default home is `DM_HOME` when set. Without `DM_HOME`, `dm` uses the platform user data directory:

- macOS: `~/Library/Application Support/darkmatter`
- Linux and other non-macOS Unix: `$XDG_DATA_HOME/darkmatter`, or `~/.local/share/darkmatter`
- Windows: `%APPDATA%\darkmatter`

Use `--home` for isolated development runs and tests.
