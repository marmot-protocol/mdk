### Breaking changes

- `RecoveryWords` and `AppGroupImageComponent` now implement `Drop` and `ZeroizeOnDrop` to erase secret buffers on
  drop; callers taking ownership of fields should borrow or use `std::mem::take` (mdk#3796).

### Fixed

- History-bundle file keys and group-image upload/download records redact `Debug` output and erase key material on
  drop, and SQLCipher salt reads enforce a size cap and omit account paths from errors (mdk#3796).
