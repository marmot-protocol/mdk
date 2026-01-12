Please refactor the code: $ARGUMENTS.

Follow these steps:

1. Identify the code to refactor from the arguments
2. Understand the current implementation
3. Identify refactoring goals:
   - Improve readability
   - Reduce duplication
   - Improve maintainability
   - Follow STYLE.md conventions
   - Better error handling
4. Plan the refactoring approach
5. Implement refactoring incrementally
6. Ensure all existing tests still pass
7. Add tests if refactoring reveals untested paths
8. Update documentation if structure changes
9. Run `just precommit` to ensure all checks pass
10. Verify test coverage maintained: `just coverage`
11. Add changelog entry if behavior changes (even if internal)
12. Create a descriptive commit message explaining the refactoring
13. Push and create a PR

Refactoring principles:
- Maintain backward compatibility (unless breaking change is intentional)
- Preserve all existing functionality
- Improve code quality without changing behavior
- Follow project style guide
- Keep tests passing
- Document significant structural changes
