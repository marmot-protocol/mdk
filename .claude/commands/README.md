# Claude Custom Commands

This directory contains custom slash commands for Claude AI in Cursor. These commands help automate common development workflows for the MDK project.

## Related Files

- **`CLAUDE.md`** (in repository root): A symlink to `AGENTS.md` that provides the development guide for AI coding agents. The symlink allows Claude to easily reference the guide while maintaining a single source of truth in `AGENTS.md`.
- **`AGENTS.md`** (in repository root): The main development guide document for AI coding agents working on the MDK codebase.

## Usage

In Cursor, you can invoke these commands using the `/` prefix followed by the command name. For example:
- `/fix-gh-issue 123` - Fix GitHub issue #123
- `/add-tests mdk-core::group::Group` - Add tests for a module
- `/fix-lints` - Fix all clippy warnings

## Available Commands

### Issue & PR Management
- **`fix-gh-issue`** - Analyze and fix a GitHub issue end-to-end
- **`review-pr`** - Review a pull request before submission

### Development Workflows
- **`add-tests`** - Add comprehensive tests for a specific module/function
- **`improve-coverage`** - Find and add tests for untested code paths
- **`refactor-code`** - Refactor code while maintaining functionality
- **`fix-lints`** - Fix all clippy warnings and formatting issues

### Code Structure
- **`add-storage-backend`** - Implement a new storage backend crate
- **`implement-trait`** - Implement a trait for a type

### Documentation & Quality
- **`update-docs`** - Update API documentation
- **`add-example`** - Create a new example
- **`verify-spec-compliance`** - Verify code matches Marmot/MLS/Nostr specs

### Maintenance
- **`update-dependencies`** - Update project dependencies
- **`update-msrv`** - Update the Minimum Supported Rust Version
- **`prepare-release`** - Prepare a new release (version bump, changelog)

## Command Format

All commands follow a consistent structure:
1. Take arguments via `$ARGUMENTS` placeholder
2. Follow numbered steps for clarity
3. Include project-specific requirements (changelog, tests, etc.)
4. End with PR creation workflow

## OpenCode Compatibility

**Yes, these commands work in OpenCode!**

OpenCode uses the same `.claude/commands/` directory structure, so all commands created here will be available in both regular Claude chat and OpenCode mode. The commands are just markdown files that Claude reads, so they work across all Cursor AI features.

## Adding New Commands

To add a new command:
1. Create a new `.md` file in this directory
2. Use `$ARGUMENTS` to accept user input
3. Follow the numbered step format
4. Include project-specific requirements (changelog, `just precommit`, etc.)
5. Reference this README or existing commands for patterns

## Project-Specific Requirements

All commands should ensure:
- ✅ Changelog entries are added
- ✅ Tests are written/updated
- ✅ `just precommit` passes before finalizing
- ✅ Code follows STYLE.md conventions
- ✅ Test coverage is maintained or improved
- ✅ PRs are created with descriptive messages
