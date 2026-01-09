Please update dependencies in the project: $ARGUMENTS.

Follow these steps:

1. Identify which dependencies to update from the arguments (or update all if not specified)
2. Check current versions in `Cargo.toml` files
3. Use `cargo update` or manually update versions in `Cargo.toml`
4. Check for breaking changes in dependency changelogs/release notes
5. Update code if needed for breaking changes
6. Run `cargo build` to check for compilation errors
7. Run `just test-all` to ensure all tests pass
8. Check for security advisories: `cargo audit` (if available)
9. Update any code that uses deprecated APIs
10. Run `just precommit` to ensure all checks pass
11. Add changelog entry if dependency updates require code changes
12. Create a descriptive commit message
13. Push and create a PR

Dependency update considerations:
- Test with both stable Rust and MSRV (1.90.0)
- Check if MSRV needs to be updated for new dependency versions
- Verify all feature flag combinations still work
- Check for new clippy warnings from updated dependencies
