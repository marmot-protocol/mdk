# dm

`dm` is the first real app surface for the Darkmatter/Marmot stack.

It is intentionally small, but it is not a smoke harness: commands are named around accounts, keys, chats, groups,
messages, and sync. Pass `--json` for a stable response envelope suitable for a future TUI.

The CLI uses `marmot-account` for account home/key storage and `marmot-app` for the runtime bridge plus Nostr
account-relay setup. `dm` can run commands directly or send them to the background `dmd` daemon over a Unix socket.

## Examples

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file account create alice
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file account create bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account bob keys publish
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account alice group create general bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account bob sync
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account alice message send <group-hex> "hello bob"
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account bob sync
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account bob chats list
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file --account bob message list --group <group-hex> --limit 20
```

Most account-scoped commands resolve the local account in this order:

1. top-level `--account <name-or-pubkey>`, before the command
2. `DM_ACCOUNT`
3. the only local account, when exactly one exists

Use `keys` for normal KeyPackage work:

```sh
dm --account bob keys publish
dm --account bob keys fetch
dm keys fetch --pubkey <npub-or-hex> --bootstrap-relays <relay-url>
```

There are no legacy aliases for this namespace; `keys` is the command.

Daemon commands:

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm --secret-store file daemon start
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm daemon status
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm daemon stop
```

Once a daemon socket exists for a home, `dm --home <path> ...` will send normal commands to `dmd`. Use `--socket` or
`DM_SOCKET` to target a specific daemon.

Chat commands are the preferred user-facing spelling for local chat projection work:

```sh
dm --account bob chats list
dm --account bob chats show <group-hex>
dm --account bob chats archive <group-hex>
dm --account bob chats unarchive <group-hex>
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
