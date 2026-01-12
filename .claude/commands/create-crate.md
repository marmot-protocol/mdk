Please create a new crate: $ARGUMENTS.

Follow these steps:

1. Understand the crate purpose and name from the arguments
2. Determine the crate location (usually `crates/mdk-{name}/`)
3. Create the crate structure:
   - `Cargo.toml` with proper metadata
   - `src/lib.rs` (or `src/main.rs` for binaries)
   - `README.md` with crate description
   - `CHANGELOG.md` following Keep a Changelog format
4. Add crate to workspace `Cargo.toml`
5. Set up dependencies and feature flags if needed
6. Add initial documentation
7. Add basic tests structure
8. Run `cargo build -p mdk-{name}` to verify it compiles
9. Run `just precommit` to ensure all checks pass
10. Add changelog entry to the new crate
11. Create a descriptive commit message
12. Push and create a PR

Crate structure requirements:
- Follow naming convention: `mdk-{name}`
- Include proper `Cargo.toml` metadata (version, authors, license, etc.)
- Add `README.md` explaining the crate's purpose
- Initialize `CHANGELOG.md` with Unreleased section
- Follow project code style (STYLE.md)
- Include workspace configuration
