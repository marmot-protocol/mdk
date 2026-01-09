Please review the pull request: $ARGUMENTS.

Follow these steps:

1. Use `gh pr view $ARGUMENTS` to get PR details
2. Use `gh pr diff $ARGUMENTS` to see the changes
3. Review the code changes for:
   - Correctness and logic
   - Code style compliance (STYLE.md)
   - Test coverage (are there tests?)
   - Changelog entries (are they present?)
   - Documentation updates (if public API changed)
   - Feature flag handling (if applicable)
   - Error handling
   - Security implications
4. Check if `just precommit` would pass:
   - Formatting
   - Clippy warnings
   - Documentation
   - Tests
5. Verify changelog format and PR links
6. Check if test coverage is maintained or improved
7. Review commit messages for clarity
8. Provide constructive feedback:
   - What looks good
   - What needs improvement
   - Specific suggestions for fixes
9. Use GitHub review tools to add comments on specific lines if needed

Review checklist:
- ✅ Code follows STYLE.md conventions
- ✅ Tests are present and comprehensive
- ✅ Changelog entries are present
- ✅ Documentation is updated (if needed)
- ✅ All checks pass (`just precommit`)
- ✅ Test coverage maintained or improved
- ✅ Error handling is appropriate
- ✅ No security concerns
