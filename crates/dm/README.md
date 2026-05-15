# dm

`dm` is the first real app surface for the Darkmatter/Marmot stack.

It is intentionally small, but it is not a smoke harness: commands are named around accounts, key packages, groups,
messages, and sync. Pass `--json` for a stable response envelope suitable for a future TUI.

The CLI uses `marmot-account` for account home/key storage and `marmot-app` for the runtime bridge plus Nostr
account-relay setup.

## Examples

```sh
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm account create alice --default-relays wss://relay.example,wss://relay2.example
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm account relay-lists --pubkey npub1... --bootstrap-relays wss://relay.example,wss://relay2.example
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm account import bob --nsec nsec1... --bootstrap-relays wss://relay.example
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm account import bob --nsec nsec1... --default-relays wss://relay.example --publish-missing-relay-lists
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm key-package publish --account bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group create --account alice --name general --member bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group list --account bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group show --account bob <group-hex>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group members --account alice <group-hex>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group invite --account alice <group-hex> --member carol
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group remove --account alice <group-hex> --member bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group archive --account bob <group-hex>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group list --account bob --include-archived
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group unarchive --account bob <group-hex>
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm group update --account alice <group-hex> --name "team room" --description "daily coordination"
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm message send --account alice --group <group-hex> hello bob
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm message list --account bob --group <group-hex> --limit 20
cargo run -p darkmatter-cli --bin dm -- --home /tmp/dm sync --account bob
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
