# AGENTS.md

This document provides instructions for AI coding agents working on the MDK (Marmot Development Kit) codebase.

## Project Overview

MDK is a Rust implementation of the [Marmot Protocol](https://github.com/marmot-protocol/marmot), which combines the MLS (Messaging Layer Security) protocol with the Nostr decentralized relay network for secure group messaging.

### Key Technologies

- **MLS Protocol**: RFC 9420 - Messaging Layer Security
- **Nostr Protocol**: Decentralized event-based messaging
- **OpenMLS**: The MLS implementation we build upon

### Crate Structure

- `mdk-core`: Main library with MLS implementation and Nostr integration
- `mdk-storage-traits`: Storage abstraction layer and trait definitions
- `mdk-memory-storage`: In-memory storage for testing
- `mdk-sqlite-storage`: SQLite-based persistent storage
- `mdk-uniffi`: UniFFI bindings for cross-platform support

## Setup Commands

```bash
# Install just (command runner)
brew install just           # macOS
cargo install just          # Other platforms

# Build the project
cargo build

# Build with all features
cargo build --all-features
```

## Testing

### Running Tests

```bash
# Run tests with all features (recommended)
just test

# Run tests without optional features
just test-no-features

# Run tests with only mip04 feature (encrypted media)
just test-mip04

# Run all test combinations (like CI)
just test-all

# Run tests for a specific crate
cargo test -p mdk-core
```

### Feature Flags

This project uses feature flags for optional functionality:

- `mip04`: Enables encrypted media support (images, files)

When adding or modifying code related to encrypted media, ensure tests are run with the `mip04` feature:

```bash
cargo test --features mip04
```

### Test Coverage

```bash
# Generate coverage summary
just coverage

# Generate HTML coverage report
just coverage-html
```

**CRITICAL**: CI enforces that test coverage must not decrease. If your PR reduces coverage (even by 0.01%), the coverage check will fail.

To maintain or improve coverage:

1. Add tests for any new code paths you introduce
2. Add tests for error handling branches
3. If your change touches existing code without adding tests, consider adding tests for related untested code paths to offset any coverage loss

The coverage workflow compares the PR's coverage against the `master` branch baseline. Coverage must stay the same or improve for the PR to pass CI.

## Code Quality Checks

### Quick Checks (Stable Rust)

```bash
# Run all checks (fmt, docs, clippy, tests)
just check

# Individual checks
just lint    # Clippy for all feature combinations
just fmt     # Format check
just docs    # Documentation check
```

## Pre-Commit Requirements

**CRITICAL**: Before every commit or pull request, you MUST run:

```bash
just precommit
```

This command:
1. Runs format, documentation, and clippy checks with stable Rust
2. Runs the same checks with MSRV (1.90.0)
3. Runs all test combinations

Do NOT skip this step. All commits must pass `just precommit` before being pushed.

### Recommended Workflow

1. During development: Use `just check` frequently (fast, stable only)
2. Before committing: Run `just precommit` (comprehensive, both Rust versions)
3. Before pushing: Ensure all checks pass locally

## Changelog Requirements

**CRITICAL**: Every change that modifies functionality must update a CHANGELOG.

### Changelog Locations

Each crate has its own changelog:

- `crates/mdk-core/CHANGELOG.md`
- `crates/mdk-storage-traits/CHANGELOG.md`
- `crates/mdk-memory-storage/CHANGELOG.md`
- `crates/mdk-sqlite-storage/CHANGELOG.md`

### Changelog Format

We follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format:

```markdown
## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated
```

### What to Document

- **Breaking changes**: API changes that require user code updates
- **Changed**: Modifications to existing functionality
- **Added**: New features, methods, or types
- **Fixed**: Bug fixes
- **Removed**: Removed features or deprecated code
- **Deprecated**: Features marked for future removal

**Important**: Always include a link to the PR at the end of each changelog entry using the format `([#123](https://github.com/marmot-protocol/mdk/pull/123))`.

Always add entries under the `## Unreleased` section of the appropriate crate's changelog.

### Markdown URL Format

**CRITICAL**: Never use bare URLs in markdown files. All URLs must be properly formatted:

- Use `[link text](url)` for inline links with descriptive text
- Use `<url>` for standalone URLs (angle bracket autolinks)
- For PR/issue references: `([#123](https://github.com/marmot-protocol/mdk/pull/123))`
- For commit references: `([abc1234](https://github.com/.../commit/abc1234...))`

This ensures compliance with markdownlint MD034 (no-bare-urls) and improves readability.

## Code Style

All Rust code must follow the project's coding style (see `STYLE.md`):

### Key Rules

- **Generics**: All trait bounds in `where` clauses, not inline
- **Self**: Use `Self` instead of the type name when possible
- **Derive order**: `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash` (in this order)
- **Logging**: Always use `tracing::warn!(...)`, never import and use `warn!(...)`
- **String conversion**: Use `.to_string()` or `.to_owned()`, not `.into()` or `String::from`
- **Imports**: Place all `use` statements at file top, never inside functions

### Import Order

```rust
// 1. core/alloc/std
use core::fmt;
use std::{...};

// 2. External crates
use crate_foo::{ ... };

// 3. Sub-module declarations
mod x;

// 4. Internal crate imports
use crate::{};
use super::{};
use self::x::Y;
```

### Control Flow

- Use `match` instead of `if let ... { } else { }`
- Use `if let` only when one arm is intentionally empty

### Sub-modules

- Define modules in separate files (`mod x;` with `x.rs`), not inline
- Exception: `#[cfg(test)] mod tests { }` and `#[cfg(bench)] mod benches { }` are inline

## Protocol References

### Marmot Protocol

- Specification: <https://github.com/marmot-protocol/marmot>
- Local specs in `/marmot` workspace folder
- Ensure all code follows the specification exactly
- Ask clarifying questions if any part of the spec is unclear

### MLS Protocol

- RFC 9420: <https://www.rfc-editor.org/rfc/rfc9420.html> (local: `docs/mls/rfc9420.txt`)
- RFC 9750 (Architecture): <https://www.rfc-editor.org/rfc/rfc9750.html> (local: `docs/mls/rfc9750.txt`)
- MLS Extensions: `docs/mls/draft-ietf-mls-extensions-08.txt`

### Nostr Protocol

- NIPs repository: <https://github.com/nostr-protocol/nips>
- Use the Nostrbook MCP server for structured NIP queries if available

## Security

- For security vulnerabilities, email **j@jeffg.me** (do not open public issues)
- MDK handles cryptographic operations - be careful with key material
- All message encryption uses MLS protocol with forward secrecy
- Review security implications of any changes to cryptographic code

## PR Checklist

Before submitting a PR:

1. ✅ Run `just precommit` - all checks must pass
2. ✅ Update CHANGELOG(s) for affected crate(s)
3. ✅ Add tests for new functionality
4. ✅ Ensure test coverage does not decrease (CI will fail if coverage drops)
5. ✅ Ensure code follows STYLE.md conventions
6. ✅ Update documentation if adding public APIs
7. ✅ Verify compatibility with MSRV (1.90.0)

## Examples

Run examples to verify functionality:

```bash
# Key package inspection
just example-keypackage

# Group inspection (requires debug-examples feature)
just example-group

# Memory storage workflow
just example-memory

# SQLite storage workflow
just example-sqlite

# Run all examples
just examples
```

