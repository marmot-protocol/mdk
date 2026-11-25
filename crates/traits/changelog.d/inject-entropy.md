### Breaking changes

- Implement `EntropySource::fill_bytes` to supply entropy (mdk#3497). The default `next_u64` reads eight
  little-endian bytes from that source.

### Added

- `OsEntropy` and `SystemWallClock` are available from `cgka_traits` for production random bytes and timestamps.
