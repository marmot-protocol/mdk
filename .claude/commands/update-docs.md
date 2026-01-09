Please update API documentation for: $ARGUMENTS.

Follow these steps:

1. Identify the module/function/type to document from the arguments
2. Review existing documentation patterns in the codebase
3. Check Rust documentation standards and best practices
4. Add or update doc comments:
   - Module-level documentation
   - Function documentation with examples
   - Type documentation
   - Error documentation
5. Include code examples in doc comments where helpful
6. Ensure all public APIs are documented
7. Run `just docs` to check documentation
8. Build docs locally: `cargo doc --open` to preview
9. Run `just precommit` to ensure all checks pass
10. Add changelog entry if documenting previously undocumented APIs
11. Create a descriptive commit message
12. Push and create a PR

Documentation standards:
- Use `///` for public API documentation
- Include examples with `# Examples` section
- Document all parameters and return values
- Document error cases
- Link to related types/functions
- Follow Rust documentation conventions
