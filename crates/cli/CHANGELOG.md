# Changelog

All notable changes to `darkmatter-cli` are tracked here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This crate uses semantic
versioning through the workspace version in the root `Cargo.toml`.

## [Unreleased]

### Changed

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
