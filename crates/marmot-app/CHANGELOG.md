# Changelog

## Unreleased

### Fixed

- Preserve verified publication across network revocation, refund interrupted acquisition claims, park denied demand without polling, and avoid permission locks around network polling. Native retries remain unchanged. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Breaking changes

- `MarmotAppConfig` adds `attachment_acquisition_mode`; full struct literals must set it or use `Default`. Handle the new terminal `AttachmentTransferState` and configuration/account `AppError` variants in exhaustive matches. `AttachmentTransferStatus` carries source MIME metadata for automatic policy observation. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Add host-managed automatic attachment demand with denied startup and generation-fenced per-account media permission. Bound network retries and stop automatic reacquisition after retention failure. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
