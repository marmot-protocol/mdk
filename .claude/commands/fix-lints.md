Please fix all clippy lints and formatting issues in the codebase.

Follow these steps:

1. Run `just lint` to identify all clippy warnings
2. Run `just fmt` to check formatting issues
3. Fix all clippy warnings (prioritize correctness, use `#[allow(clippy::...)]` only when necessary with justification)
4. Fix all formatting issues with `cargo fmt`
5. Run `just lint-all` to check all feature combinations
6. Run `just precommit` to ensure everything passes
7. If changes are made, add a changelog entry
8. Create a descriptive commit message
9. Push and create a PR if significant changes were made

Focus areas:
- Unused imports/variables
- Clippy suggestions for code improvements
- Formatting consistency
- Dead code removal
