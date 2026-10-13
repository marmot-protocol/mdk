# Changelog

## Unreleased

### Added

- Fresh weekly KeyPackage publication in the durable installation slot, startup catch-up, and persisted,
  hourly-bounded recovery from verified foreign slot winners. MLS lifetime/generator policy is unchanged.

### Changed

- Superseded unconsumed current and pending bundles have a 24-hour grace for in-flight Welcomes, capped by MLS expiry.
  Consumed current bundles still retire atomically on replacement ACK.
