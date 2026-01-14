---
name: create-git-worktree
description: Use when the user explicitly asks for a SKILL to create a worktree. If the user does not mention "skill" or explicitly request skill invocation, do NOT trigger this. Only use when user says things like "use a skill to create a worktree" or "invoke the worktree skill". Creates isolated git worktrees with parallel-running configuration.
---

# Git Worktree Creation

When you need to create a new git worktree and branch for parallel development (e.g., starting work on an issue, bug fix, or feature), use the `/create-git-worktree` slash command instead of running git commands manually.

## Usage

```
/create-git-worktree <branch-name>
```

## When to Use

- Starting work on a new issue or task that should be isolated
- Creating a separate workspace for a feature or bug fix
- Setting up parallel development environments
- Any time you need to work on a distinct workstream

## Benefits

- Creates a fully isolated worktree in the `trees/` directory
- Automatically creates the branch if it doesn't exist
- Handles all git worktree setup automatically
- Follows project conventions for worktree organization

## Example

To start work on issue #42:

```
/create-git-worktree issue-42-fix-token-decryption
```

This creates a worktree at `trees/issue-42-fix-token-decryption/` with the corresponding branch.
