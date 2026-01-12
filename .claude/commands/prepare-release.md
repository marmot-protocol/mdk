Please prepare a release: $ARGUMENTS.

Follow these steps:

1. Determine the release version from arguments (e.g., "0.1.0" or "v0.1.0")
2. Identify which crates need version bumps (check all `Cargo.toml` files)
3. Update version numbers in all relevant `Cargo.toml` files
4. Consolidate changelogs:
   - Move entries from "Unreleased" to new version section
   - Format: `## [X.Y.Z] - YYYY-MM-DD`
   - Include all changes from all crates
5. Create a git tag: `git tag -a v{X.Y.Z} -m "Release v{X.Y.Z}"`
6. Update any version references in documentation
7. Verify all tests pass: `just test-all`
8. Run `just precommit` to ensure all checks pass
9. Create release commit with message: `chore: release v{X.Y.Z}`
10. Push commits and tags: `git push && git push --tags`
11. Create GitHub release using `gh release create` with changelog content

Release checklist:
- ✅ All crate versions updated
- ✅ Changelogs consolidated and formatted
- ✅ Git tag created
- ✅ All tests pass
- ✅ Documentation updated
- ✅ Ready for publishing to crates.io (if applicable)
