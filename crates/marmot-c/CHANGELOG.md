# Changelog - marmot-c

All notable changes to the Marmot C bindings.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions track the workspace version; releases are tagged `marmotc-v<version>`.

## [Unreleased]

### Added

- `marmot_notify_connectivity_restored`, allowing C hosts to wake durable
  outbound retries immediately after usable connectivity returns.
- Initial C ABI over `marmot-uniffi`: client lifecycle, accounts, groups,
  messaging, media, notifications, push, relays/telemetry, audit logs,
  timeline reads, Markdown parsing, and the 8 subscription surfaces with
  blocking reads and callback pumps. ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))
- cbindgen-generated `include/marmot.h` (checked in, CI diff-gated),
  cdylib + staticlib build, pkg-config file, and the `marmotc-v*` release
  bundle. ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))
- `alloc-audit` test feature proving deep-free completeness; C smoke
  example run under gcc, clang, and valgrind in CI. ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))
- `marmot_client_new_with_secret_store` plus the `MarmotSecretStore`
  callback vtable and `MarmotSecretStoreStatus`: a host can hold account
  signing keys in its own storage (an encrypted vault, a custom keystore)
  instead of the platform keychain. `marmot_client_new` is unchanged.
  ([#1575](https://github.com/marmot-protocol/mdk/pull/1575))
- `marmot_rotate_key_package`: rotate the account's KeyPackage under its
  proper name (with a matching `rotate_key_package` on the UniFFI
  surface); `marmot_publish_new_key_package` stays as the legacy alias.
  ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))

  Closes [#328](https://github.com/marmot-protocol/mdk/issues/328)
- `marmot_user_relay_lists` and `marmot_refresh_user_relay_lists`: read or
  fetch the NIP-65 and inbox relay lists any account id has published, not
  just a local account's. Both return `MarmotAccountRelayLists`.
  ([#1605](https://github.com/marmot-protocol/mdk/pull/1605))
