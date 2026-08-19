---
title: "Terminal Harness Execution Profiles"
created: 2026-08-19
updated: 2026-08-19
tags: [marmot, overview, terminal-harness, permissions, sandbox]
status: overview
---

# Terminal Harness Execution Profiles

Marmot terminal harnesses accept remote prompts from explicitly allowed
senders, then invoke a local coding-agent backend. A shared profile expresses
operator intent while backend adapters preserve the real differences between
Pi, OpenCode, and Codex.

## Shared Intent

`MARMOT_HARNESS_EXECUTION_PROFILE` has three values:

- `inherit`: add no connector-side policy overrides.
- `autonomous`: do not wait for interactive approvals, while preserving hard
  denies and isolation where supported.
- `unrestricted`: request the broadest non-interactive backend mode. External
  isolation is mandatory.

This is deliberately not a `yolo` boolean. Approval prompts, logical tool
permissions, process sandboxing, and network policy are different controls.

## Capability Matrix

| Backend | Approval mapping | Isolation mapping | Version failure behavior |
| --- | --- | --- | --- |
| Pi | Non-interactive execution is natively approval-free for every profile | No built-in OS sandbox | No profile-specific CLI feature is required |
| OpenCode | `autonomous` uses `--auto`; `unrestricted` adds a process-local allow-all permission overlay | Logical permissions only; no OS sandbox | An unsupported `--auto` fails the invocation; no successful reply is sent |
| Codex | `autonomous` sets `approval_policy="never"`; `unrestricted` bypasses approvals | Configured sandbox/network survive `autonomous`; `unrestricted` bypasses the sandbox | An unsupported invocation-local config override or flag fails the invocation; no successful reply is sent |

The OpenCode overlay exists only in the child process environment. The Codex
override exists only in that invocation. Connector setup never rewrites global
Pi, OpenCode, or Codex configuration.

## Installer Contract

The shared installer writes the selected profile into the private harness env
file and same-user service definition. It requires
`--acknowledge-unrestricted` before writing `unrestricted`; `--yes`, dry-run,
or an environment-provided profile do not substitute for that acknowledgement.

Startup tracing contains only the profile and fixed capability state names.
Unsupported or malformed profiles fail configuration loading.

## Security Boundary

An allowed Marmot sender plus `unrestricted` is effectively remote code
execution as the harness service user. Sender allowlisting authenticates who
may request work; it does not constrain what an unrestricted backend may do.

The `/<path>` picker selects a working directory beneath `$HOME`. It is not a
filesystem, process, credential, or network containment boundary. Unrestricted
deployments should use a dedicated OS user, container, or VM with narrowly
scoped credentials and host access. Backend logical permission checks must not
be described as an OS sandbox.
