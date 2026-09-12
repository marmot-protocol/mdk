# Changelog - marmot-c

All notable changes to the Marmot C bindings.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions track the workspace version; releases are tagged `marmotc-v<version>`.

## [Unreleased]

### Added

- Typed attachment diagnostics (`MarmotMediaDiagnostic`, closed stage/code/field
  enums, `MarmotMediaAttachmentResult`, and `MarmotMediaAttachmentProjection`)
  plus `_v2` query, snapshot, next, pagination, and event/projection mirrors
  that retain rejected attachments and their original indices.
- `marmot_last_media_error` takes and clears the thread-local typed diagnostic
  after `MARMOT_STATUS_MEDIA_ATTACHMENT` (70). Non-media failures clear a stale
  diagnostic.
- `marmot_parse_media_imeta_tag` mirrors the existing UniFFI explicit parser.

### Changed

- Legacy `marmot_list_media`, message, timeline, and event layouts are
  unchanged diagnostic-loss compatibility views: rejected attachments are
  omitted and old records do not carry `media_attachments`. Use the `_v2`
  symbols for the rich outcome tree. Rebuild against the regenerated header.

## [0.9.21] - 2026-09-10

This cohort also exposes host-driven agent stream publishing and the v4 audit
tracker configuration. Rebuild with the matching header and library. Account
storage advances through migrations 68–69; back up before upgrading because
downgrade is unsupported. See the [cohort upgrade notes](../cli/CHANGELOG.md#0921---2026-09-10).

### Added

- Additive `MarmotMarkdownBlock::Details` with an indirect `MarmotMarkdownDetails`
  payload for bounded `<details>` / `<summary>` display blocks. Existing block
  discriminants and union stride are unchanged; C consumers must regenerate
  compatible bindings to render the new tag.
- `marmot_search_cached_users`, `MarmotUserDirectorySearchResultList`, and
  `marmot_user_directory_search_result_list_free` for network-free public cache search across connected accounts.

### Changed

- Group creation, invites, and composition prewarming fetch current KeyPackages from relays, including for local
  sibling accounts; cached packages no longer substitute when resolution fails. Prewarm retains discovery routes
  only, and `MarmotMemberKeyPackagePrewarmSummary::reused_members` remains present but always returns zero.
- Create and Invite reject KeyPackages that explicitly advertise RFC 9420 default extension/proposal capabilities.
  **Compatibility:** inviting a peer still publishing an affected package fails (`InvalidKeyPackageCapabilities` in
  the Rust engine) until that peer generates and publishes a conforming package. Upgraded recipients automatically
  regenerate once on account activation; the durable generator revision advances only after a relay ACK, with
  retries across restarts. Peers that have not upgraded are not repaired by a sender's upgrade. This deliberately
  keeps nonconforming signed leaves out of new membership state. Previous unused private bundles retain their
  expiry/consumption policy and historical Welcome processing is unchanged.

- Search results include `is_followed_by_searcher`; streaming updates include keyed `updated_results` replacements
  and a `CachedResultsFound` trigger. Consumers must merge by account ID, including across radius pages, and use
  the explicit follow flag instead of radius 1 for badges. C consumers must rebuild against the matching generated
  header and library because both search-result and search-update struct layouts changed.

## [0.9.20] - 2026-09-08

### Added

- Presented chat-list reads and subscriptions, chat presentation records, and
  unified usage-diagnostics consent and settings APIs.
- Explicit onboarding recovery/query and epoch-aware approval/acknowledgment
  commands. `MarmotOnboardingSnapshot` includes `recovery_epoch`; C consumers
  must rebuild against the matching generated header and library.

### Changed

- `marmot_cancel_onboarding` documentation now matches the runtime: approved or
  ready attempts may be cancelled without first resuming a repair.

## [0.9.16] - 2026-09-01

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

[Unreleased]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.9.20...HEAD
[0.9.20]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.9.19...marmotc-v0.9.20
[0.9.16]: https://github.com/marmot-protocol/mdk/releases/tag/marmotc-v0.9.16
