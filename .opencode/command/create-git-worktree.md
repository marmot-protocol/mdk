---
description: Create a new git worktree and branch
agent: build
subtask: true
model: openrouter/anthropic/claude-haiku-4.5
---

# Purpose

Create a new git worktree in the `trees/` directory with completely isolated configuration for parallel execution. This enables working on multiple workstreams or issues in parallel.

## Instructions

- This is a ONE-SHOT command that creates a worktree automatically
- Creates a fully functional, isolated clone of the codebase in a separate worktree
- If branch doesn't exist locally, create it from current HEAD
- If branch exists but isn't checked out, create worktree from it

## Workflow

### 1. Parse and Validate Arguments

- Read BRANCH_NAME from $ARGUMENTS, error if missing
- Validate branch name format (no spaces, valid git branch name)

### 2. Pre-Creation Validation

- Check if PROJECT_CWD/trees/ directory exists, create if not: `mkdir -p trees`
- Verify trees/ is in PROJECT_CWD/.gitignore (should be there already)
- Check if worktree already exists at WORKTREE_DIR
- Check if branch exists: `git branch --list <BRANCH_NAME>`
  - If branch doesn't exist, will create it in next step
  - If branch exists, will checkout to create worktree

### 3. Create Git Worktree

- From PROJECT_CWD, create worktree with: `git worktree add trees/<BRANCH_NAME> <BRANCH_NAME>`
  - If branch doesn't exist, this creates it from HEAD
  - If branch exists, this checks it out in the worktree
  - This creates WORKTREE_DIR at PROJECT_CWD/trees/<BRANCH_NAME>
- Verify worktree was created: `git worktree list | grep trees/<BRANCH_NAME>`
- You're now ready to start work in this worktree & branch
