### Breaking changes

- `open_history`, `open_with_recovery_key`, and the corresponding `Engine` methods now return redacted-`Debug`
  zeroizing `SecretBytes` instead of `Vec<u8>` (mdk#3796).

### Fixed

- Audit error details use a closed classifier rather than forwarding raw error display strings, and
  `OpenMlsProjectionError::Display` omits raw message identifiers (mdk#3796).
