### Breaking changes

- `MarmotAppEventError::Json` now carries a closed `MarmotAppEventJsonError` category instead of a raw `String`,
  `SecretBytes` is now a zeroizing newtype with redacted `Debug` output, `DeviceRosterV1::leaf_tag_key` is
  `Zeroizing<[u8; 32]>` with redacted `Debug` output, and `GroupBlossomImageV1` implements `Drop` and
  `ZeroizeOnDrop` to erase key material on drop (mdk#3796).
