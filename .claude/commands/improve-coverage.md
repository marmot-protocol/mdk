Please improve test coverage by finding and adding tests for untested code.

Follow these steps:

1. Run `just coverage` to get current coverage report
2. Identify modules/functions with low or zero coverage
3. Prioritize:
   - Public API functions
   - Error handling paths
   - Edge cases and boundary conditions
   - Recently added code
4. Add comprehensive tests for identified gaps
5. Ensure tests cover:
   - Happy paths
   - Error cases
   - Edge cases
   - All feature flag combinations (if applicable)
6. Run tests with relevant feature flags: `just test`, `just test-mip04`, etc.
7. Verify coverage improved: `just coverage`
8. Run `just precommit` to ensure all checks pass
9. Add changelog entry if significant coverage improvements
10. Create a descriptive commit message
11. Push and create a PR

Remember:
- Test coverage must not decrease (CI enforces this)
- Add tests for error handling branches
- Consider both unit and integration tests
- Test with all relevant feature flag combinations
