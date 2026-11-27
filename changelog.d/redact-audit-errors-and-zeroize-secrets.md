### Breaking changes

- `MarmotAppEventError::Json` now carries a closed `MarmotAppEventJsonError` category instead of raw parser text,
  `SecretBytes` is now a redacted-`Debug` zeroizing newtype returned by `open_history` and `open_with_recovery_key`,
  `DeviceRosterV1::leaf_tag_key` is wrapped in `Zeroizing<[u8; 32]>`, and `GroupBlossomImageV1`,
  `AppGroupImageComponent`, and `RecoveryWords` implement `Drop` and `ZeroizeOnDrop` (mdk#3796).

### Fixed

- Engine audit error details use a closed classifier without forwarding free-form error text, projection error display
  omits raw message identifiers, symmetric key holders and group-image transfer types redact `Debug` output and erase
  keys on drop, and SQLCipher salt reads enforce a size limit without including account paths in errors (mdk#3796).
