Please create a new example: $ARGUMENTS.

Follow these steps:

1. Understand the example requirements from the arguments
2. Review existing examples in `examples/` directory for patterns
3. Check `justfile` for example-related commands
4. Create the example file following naming conventions
5. Implement the example with:
   - Clear comments explaining each step
   - Error handling
   - Useful output/logging
6. Add example to `Cargo.toml` if needed
7. Add a `just` command to run the example (if appropriate)
8. Test the example runs successfully
9. Update README.md if examples are listed there
10. Add changelog entry if example demonstrates new functionality
11. Run `just precommit` to ensure all checks pass
12. Create a descriptive commit message
13. Push and create a PR

Example requirements:
- Should be runnable: `cargo run --example {name}`
- Should demonstrate real use cases
- Should include helpful comments
- Should handle errors gracefully
- Should produce useful output
