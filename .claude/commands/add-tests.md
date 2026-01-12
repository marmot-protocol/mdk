Please add comprehensive tests for: $ARGUMENTS.

Follow these steps:

1. Identify the module/function/feature to test from the arguments
2. Search the codebase to understand the code structure
3. Review existing tests for similar patterns
4. Identify test gaps:
   - Happy paths
   - Error cases
   - Edge cases
   - Boundary conditions
   - Feature flag combinations (if applicable)
5. Write comprehensive test cases
6. Ensure tests follow existing test patterns and conventions
7. Run tests with relevant feature flags:
   - `just test` for all features
   - `just test-mip04` if testing encrypted media
   - `just test-no-features` for base functionality
8. Verify test coverage improved: `just coverage`
9. Run `just precommit` to ensure all checks pass
10. Add changelog entry if adding significant test coverage
11. Create a descriptive commit message
12. Push and create a PR

Test organization:
- Unit tests in `#[cfg(test)] mod tests { }` blocks
- Integration tests in `tests/` directory
- Use descriptive test names that explain what is being tested
- Make sure you follow the instructions in CLAUDE.md about where to put imports
