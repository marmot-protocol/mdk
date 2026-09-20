# Changelog

## Unreleased

### Breaking changes

- `MarmotOptions` gains an optional acquisition mode and transfer state gains three terminal variants. Regenerate Kotlin/Swift bindings with the matching library and update exhaustive state handling. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Expose host-managed acquisition mode, generation-fenced permission updates and atomic automatic requests to Kotlin/Swift. Add terminal history/budget outcomes; regenerate bindings with matching native libraries. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
