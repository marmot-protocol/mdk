# MDK Development Guide for AI Agents

This document provides instructions for AI coding agents working on the MDK (Marmot Development Kit) codebase. This will work for most major AI harnesses. The `CLAUDE.md` file in this repo is a symlink to this doc.

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

**CRITICAL**: Before every commit or pull request, you MUST run pre-commit checks. All commits must pass before being pushed.

### For AI Agents

**Always use `just precommit`** (quiet mode). This produces minimal, structured output that is easy to parse:

```bash
just precommit
```

Example output on success:

```text
  fmt (stable)...          ✓
  docs (stable)...         ✓
  clippy (stable)...       ✓
  fmt (msrv)...            ✓
  docs (msrv)...           ✓
  clippy (msrv)...         ✓
  test (all features)...   ✓
  test (no features)...    ✓
  test (mip04)...          ✓
PRECOMMIT PASSED
```

On failure, only the failing step's full output is shown, making it straightforward to identify and fix the issue:

```text
  fmt (stable)...          ✓
  docs (stable)...         ✓
  clippy (stable)...       ✗

<full clippy error output here>
```

### For Humans

Use `just precommit-verbose` for full output from every step:

```bash
just precommit-verbose
```

### What Precommit Checks

1. Format, documentation, and clippy checks with **stable** Rust
2. The same checks with **MSRV** (1.90.0)
3. All test combinations (all features, no features, mip04-only)

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

**Note**: Always reference the PR number, not the issue number, in changelog entries. This means you may need to push the branch and create a PR before updating the changelog, so that you have a PR number to reference.

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
- **Imports**: Place all `use` statements at the top of their scope (see Import Placement below)

### Import Placement (CRITICAL)

**All `use` statements must be placed at the TOP of their containing scope.** Never place imports inside functions, methods, or blocks.

This rule applies to:

1. **Regular code**: Imports at the top of the file
2. **Test modules**: Imports at the top of `mod tests { ... }`, not inside individual test functions
3. **Nested test modules**: Imports at the top of each nested module
4. **Conditionally-compiled code** (`#[cfg(unix)]`): Move the import to the top with the same `#[cfg(...)]` attribute

```rust
// GOOD - conditional import at file/module top
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn set_permissions(path: &Path) -> Result<(), Error> {
    let perms = std::fs::Permissions::from_mode(0o600);
    // ...
}

// BAD - import inside function
#[cfg(unix)]
fn set_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;  // ❌ WRONG!
    let perms = std::fs::Permissions::from_mode(0o600);
    // ...
}
```

```rust
// GOOD - test imports at module top
#[cfg(test)]
mod tests {
    use mdk_storage_traits::groups::GroupStorage;
    use nostr::EventId;

    use super::*;

    #[test]
    fn test_something() {
        // Use GroupStorage here - no import needed
    }
}

// BAD - imports inside test functions
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        use mdk_storage_traits::groups::GroupStorage;  // ❌ WRONG!
    }
}
```

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

- For security vulnerabilities, email **<j@ipf.dev>** (do not open public issues)
- MDK handles cryptographic operations - be careful with key material
- All message encryption uses MLS protocol with forward secrecy
- Review security implications of any changes to cryptographic code
- All crates use `#![forbid(unsafe_code)]` or `#![deny(unsafe_code)]`

### Sensitive Identifiers - NEVER Log or Expose

**CRITICAL**: The following identifiers are privacy-sensitive and must NEVER be included in:

- Log messages (via `tracing::*` macros)
- Error messages or error strings
- Debug output (including `Debug` trait implementations for types containing these)
- Panic messages
- User-facing error descriptions

| Identifier | Description | Why It's Sensitive |
|------------|-------------|-------------------|
| Encryption keys | Any key material | Obviously sensitive cryptographic data |
| Exporter secrets | MLS exporter secrets | Enables retrospective traffic decryption |
| `mls_group_id` | MLS group identifier (32 bytes) | Enables cross-system group linkage and tracking |
| `nostr_group_id` | Nostr group identifier | Links Nostr events to MLS groups |

#### What to Do Instead

When writing error messages for "not found" or similar conditions:

```rust
// GOOD - Generic error without identifier
GroupError::NotFound("Group not found".to_string())

// GOOD - Use a non-identifying error variant
GroupError::GroupNotFound

// BAD - Leaks the MLS group ID
GroupError::InvalidParameters(format!("Group with MLS ID {:?} not found", mls_group_id))

// BAD - Leaks group identifier in logs
tracing::warn!("Group {} not found", mls_group_id);
```

This requirement stems from [MIP-01](https://github.com/marmot-protocol/marmot) group identity and privacy guidance. Violations can enable attackers or operators to exfiltrate private identifiers from logs, allowing cross-system linkage of groups and weakening metadata privacy guarantees.

See also: `SECURITY.md` for the full threat model and security considerations.

### Cryptographic Code Requirements

When writing or modifying cryptographic code:

#### Key Generation
- MUST use `getrandom` for all key generation (CSPRNG)
- Never use weak RNGs (`rand::thread_rng()` alone, etc.)
- Keys should be 256-bit (32 bytes) minimum for symmetric operations

#### Authenticated Encryption
- Use ChaCha20-Poly1305 or AES-GCM (authenticated modes only)
- Never use unauthenticated encryption (AES-CBC alone, etc.)
- Nonces must be randomly generated and never reused with the same key

#### Key Derivation
- Use HKDF with proper domain separation via unique context strings
- Context strings should identify protocol and purpose (e.g., `mip01-image-encryption-v2`)

#### Zeroization
- Use `Secret<T>` wrapper for sensitive values
- Derive `ZeroizeOnDrop` for types containing key material
- Don't implement `Copy` for types with sensitive data

### Identity Binding Security

For key packages and credentials, the credential identity MUST match the event signer:

```rust
// CRITICAL - prevents impersonation attacks
if credential_identity != event.pubkey {
    return Err(Error::KeyPackageIdentityMismatch { ... });
}
```

Base64 encoding MUST include explicit encoding tags per MIP-00/MIP-02. Reject data without tags to prevent downgrade attacks.

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

