# Changelog

All notable changes to `darkmatter-cli` are tracked here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This crate uses semantic
versioning through the workspace version in the root `Cargo.toml`.

## [Unreleased]

### Added

- Added `dm stream start`, `dm stream finish`, and `dm stream verify` for anchoring agent text
  stream starts/finals through normal encrypted Marmot messages and checking QUIC transcript hashes.
- Added `dm stream watch` and `dm stream send --broker` for brokered QUIC preview streams anchored by the
  durable start message.
- Added `dm stream receive` and `dm stream send` for provisional raw QUIC agent text stream previews.

### Changed

- `dmd` now keeps long-lived per-account relay subscriptions for real WebSocket relays instead of rebuilding
  subscriptions on every sync interval.
- `dm account create --relay <url>` now publishes the required NIP-65, inbox, and KeyPackage relay lists for
  new local signing accounts when command-specific relay-list flags are omitted.
- Imported `nsec` accounts now require `--publish-missing-relay-lists` before publishing missing required relay
  lists discovered from bootstrap relays.
- Removed the file-backed local transport and Marmot Lab crate; local tests now use Nostr SDK mock relays and
  product flows require relay-backed setup.
- Moved the CLI crate source directory from `crates/dm` to `crates/cli`. The Cargo package remains
  `darkmatter-cli`, and the installed binaries remain `dm` and `dmd`.

## [0.1.0] - 2026-05-17

Initial release of the `dm` command-line app, the `dmd` background daemon, and the Ratatui TUI.

### Added

- `dm` account commands for creating local signing accounts, adding public-only accounts, listing local
  accounts, inspecting account status, and checking relay-list readiness.
- `dm keys` commands for publishing the selected account's KeyPackage and fetching another account's latest
  KeyPackage from bootstrap relays.
- `dm group`, `dm chats`, `dm message`, and `dm sync` commands for creating encrypted groups, managing members,
  sending/listing messages, archiving chat projections, and processing relay events for a local account.
- Stable `--json` response envelopes for scripts, daemon forwarding, and TUI integration.
- `dmd` daemon support for socket-backed command execution, pid/log files, daemon status reporting, background
  sync, and app-level Nostr user-directory warming.
- `dm tui`, a terminal interface over the real CLI/daemon command surface with account selection, chat
  navigation, message sending, slash commands, daemon controls, account onboarding, and member management.
- Local installation docs for `cargo install --path crates/cli --locked --bins`.
- Homebrew release checklist and namespaced tap packaging path for `marmot-protocol/tap/darkmatter`.

[Unreleased]: https://github.com/marmot-protocol/darkmatter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/marmot-protocol/darkmatter/releases/tag/v0.1.0
