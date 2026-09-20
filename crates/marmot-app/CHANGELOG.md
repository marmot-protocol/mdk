# Changelog

## Unreleased

### Breaking changes

- `MarmotAppConfig` adds `attachment_acquisition_mode`; full struct literals must set it or use `Default`. Handle the new terminal `AttachmentTransferState` variants in exhaustive matches. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Add host-managed automatic attachment demand with denied startup and generation-fenced per-account media permission. Bound network retries and stop automatic reacquisition after retention failure. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
