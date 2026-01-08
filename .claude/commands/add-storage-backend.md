Please implement a new storage backend: $ARGUMENTS.

Follow these steps:

1. Understand the storage backend requirements from the arguments
2. Review `mdk-storage-traits` to understand the storage trait interface
3. Review existing implementations (`mdk-memory-storage`, `mdk-sqlite-storage`) for patterns
4. Create a new crate following the naming pattern: `mdk-{backend}-storage`
5. Implement all required traits from `mdk-storage-traits`
6. Add comprehensive tests (unit and integration)
7. Add example usage (if applicable)
8. Update workspace `Cargo.toml` to include the new crate
9. Add crate documentation
10. Add changelog entries:
    - New crate changelog: `crates/mdk-{backend}-storage/CHANGELOG.md`
    - Update `mdk-storage-traits/CHANGELOG.md` if traits were extended
11. Run `just precommit` to ensure all checks pass
12. Verify test coverage: `just coverage`
13. Create a descriptive commit message
14. Push and create a PR
15. Update changelogs with PR link

Storage backend requirements:
- Implement `Storage` trait from `mdk-storage-traits`
- Handle all error cases gracefully
- Provide clear error messages
- Support all required operations (create, read, update, delete)
- Include migration support if needed
