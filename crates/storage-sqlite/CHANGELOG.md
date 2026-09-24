# Changelog

## Unreleased

### Added

- Add qualified recovery scope checkpoints, independent completion predicates, exact loss
  acknowledgment guards and atomic inventory invalidation. Schema 0093 preserves existing
  demand/retry evidence and bounds serialized explicit-history callers to one row. This
  storage slice remains gated on coordinated runtime owner integration. (#1946)

- Add schema 0092 recovery-ledger groundwork: migrate overflow and epoch demand, preserve
  release/maintenance/inventory evidence, and provide restart-safe attempt reservations.
  Legacy storage APIs use the new ledger. Runtime owner integration is still required. (#1946)

## 0.10.4 - 2026-09-20

### Fixed

- Clear permission pause on terminal failure, share MIME permission classification, and avoid idle permission-resume write transactions and redundant demand updates. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Initialize upgrade budgets at zero, preserve paused deadlines and partial ciphertext, and retain size-policy diagnostics when budgets are exhausted. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Migrations 88–89 add a blob-free draft attachment-descriptor index and durable token-correlated local submissions.
  Locally accepted sends survive restart and transfer ownership atomically to the engine queue. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- Chat-list previews expose the selected message's pinned retention duration and expiry directly from its source record, including decisions finalized after local admission. No database migration is required. ([#1942](https://github.com/marmot-protocol/mdk/pull/1942))

- Migration 87 preserves acquired-but-unavailable history and persists completed receipts and opt-in budgets of four
  acquisitions and 64 network attempts. Upgrade preserves native retry behavior and existing work. Automatic demand
  atomically preserves suppression, deadlines and outcomes. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
