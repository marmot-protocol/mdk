---
description: Verify and fix an issue from github
agent: build
subtask: false
---

# Purpose

Verify a specific issue from github is a valid issue and then work to fix the issue. Once finished, create a commit and PR for github.

## Instructions

### 1. Parse and Validate Arguments

- Read ISSUE_NUMBER from $ARGUMENTS, this could be either a bare number (e.g. 5), an issue number (e.g. #5), or a full url (e.g. https://github.com/org/repo/issues/5). You want to isolate the number in order to find the issue on github using `gh`. If you fail to parse the number, throw an error and stop.

### 2. Validate Issue

- Read the issue and then locate and read any files related to the issue in the codebase to better understand the issue context.
- Determine if the issue is a valid problem, feature, or task that should be worked on.
- If not, return a message explaining why we shouldn't work on it and stop.
- If so, continue.

### 2. Fix Issue

- Based on the issue title and content, come up with a very short ISSUE_DESCRIPTION.
- The BRANCH_NAME is `issue_<ISSUE_NUMBER>_<ISSUE_SECRIPTION>`.
- Create a new git worktree with the `create-git-worktree` skill, using <BRANCH_NAME> as the argument.
- Once you have the new worktree, work on the issue until you're done.
- Once you have finished the issue, run all quality checks (`just ci`) and check code coverage (`just coverage-text`).
    - All quality checks must pass
    - Code coverage must be equal or greater than it is on HEAD
- Commit your changes with a descriptive commit message and create a PR on github. Make sure to mention `Closes #<ISSUE NUMBER>` in the PR comment.

### 3. Report

After successful PR creation provide a detailed report in the following format:

✅ Issue #<ISSUE_NUMBER> Successfully Completed!

📁 Worktree Details:
   Location: trees/<BRANCH_NAME>
   Branch: <BRANCH_NAME>

🔗 GitHub Details:
   Issue: <FULL_ISSUE_URL>
   PR: <FULL_PR_URL>

🪏 Work Summary:

   <Summary of changes made>
