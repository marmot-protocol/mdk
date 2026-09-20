# Changelog

## Unreleased

### Fixed

- Initialize upgrade budgets at zero, preserve paused deadlines and partial ciphertext, and retain size-policy diagnostics when budgets are exhausted. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Preserve acquired-but-unavailable history; persist completed receipts and opt-in budgets of four acquisitions and 64 network attempts. Upgrade preserves native retry behavior and existing work. Automatic demand atomically preserves suppression, deadlines and outcomes. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
