# Changelog

## Unreleased

### Fixed

- Judge epoch-backfill overflow retry backoff by the durable delay. A loaded runner
  can spend more than a second after that reservation is written, which previously
  failed a test that still required nearly the full cooldown to be remaining.

### Changed

- Restrict the account-local overflow marker writer to durable loss evidence. The account
  mutation path imports that evidence into recovery demand; runtime dispatch consolidation
  remains separate integration work. (#1946)

### Breaking changes

- `HostPerformanceOperation` and `RuntimePerformanceOperation` gain 28 shared and
  nine Linux-specific host stages. Downstream exhaustive Rust matches must handle
  the new variants. The snapshot struct layout is unchanged; stages appear in
  `runtime_operations`.

### Added

- Route reviewed host stages through the existing runtime telemetry registry,
  including its fixed metric names and all five outcomes in snapshots and OTLP.

## 0.10.4 - 2026-09-20

### Fixed

- Keep pure explicit downloads outside automatic budgets and defer transient disk pressure before the verified-body receipt. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Preserve verified publication across network revocation, refund interrupted acquisition claims, park denied demand without polling, and avoid permission locks around network polling. Native retries remain unchanged. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Make locally accepted pending rows visible to conversation-window navigation before relay publication completes and
  avoid unused attachment plaintext hydration during draft saves. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- Apply execution-based exponential backoff to repeated epoch-backfill overflow failures. ([#1949](https://github.com/marmot-protocol/mdk/pull/1949))

### Breaking changes

- `MarmotAppConfig` adds `attachment_acquisition_mode`; full struct literals must set it or use `Default`. Handle the new terminal `AttachmentTransferState` and configuration/account `AppError` variants in exhaustive matches. `AttachmentTransferStatus` carries source MIME metadata for automatic policy observation. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Add host-managed automatic attachment demand with denied startup and generation-fenced per-account media permission. Bound network retries and stop automatic reacquisition after retention failure. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Add durable token-correlated local send admission and restart recovery without changing existing send-method
  completion semantics. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))
