Please implement a trait: $ARGUMENTS.

Follow these steps:

1. Identify the trait to implement from the arguments
2. Search the codebase to understand the trait definition
3. Identify which type should implement the trait
4. Review existing trait implementations for patterns
5. Implement all required methods:
   - Follow STYLE.md conventions
   - Use `where` clauses for trait bounds
   - Use `Self` where possible
   - Add proper error handling
6. Add comprehensive tests for the trait implementation
7. Add documentation with examples
8. Run `just test` to verify implementation
9. Run `just precommit` to ensure all checks pass
10. Add changelog entry
11. Create a descriptive commit message
12. Push and create a PR

Trait implementation requirements:
- Implement all required methods
- Consider default implementations for optional methods
- Add tests covering all methods
- Document behavior and any invariants
- Handle errors appropriately
- Follow project code style
