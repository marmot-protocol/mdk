# Integration guide authoring template

Copy this structure into `<version>.md`; replace the prompts with verified release-specific
content. This file is an authoring aid, not a guide for a shipped version. Use
[the release documentation checklist](../../release.md#release-documentation).

## Scope and provenance

Name the baseline and target versions, peeled source SHAs, affected artifact tracks and
intended readers. Link the concise release notes and previous integration guide. If this
is a post-tag supplement, say so and use a documentation-commit link in published notes.

## Upgrade decisions

Provide a compact table separating mandatory source/binary/schema adaptation, changed
defaults, optional features and automatic fixes. Include behavioral changes even when
method signatures did not change. A no-action release still needs an explicit statement.

## Required upgrade steps

Explain matching generated-source/native/header/resources, platform prerequisites, data
migration, rollback limits and changed record/enum/error handling. Link distribution and
storage contracts; distinguish newly changed requirements from existing ones to preserve.

## Feature integration sections

For every client-visible change: explain why it exists, preferred methods and older
alternatives, call ordering, inputs/outputs, local/network behavior, state/error handling,
cancellation/ownership, bounds/paging, privacy/localization, and Swift/Kotlin/C differences.
Use compile-checked examples or explicitly label illustrative snippets. Do not invent a
formal deprecation schedule for supported primitives. Link detailed contracts without
forcing readers to reconstruct the upgrade sequence themselves.

## Changes requiring no new calls

List applicable runtime fixes and their client-visible effects. Identify behavior already
in the baseline and planned work not present in the target. Avoid release/adoption claims
that exceed the evidence.

## Acceptance and remaining work

Give a concrete consumer checklist, platform/device scenarios, evidence stages and known
limitations. Include lifecycle/offline/error/cancellation paths as appropriate. Record
what was actually validated separately from checks the client still needs to perform.
