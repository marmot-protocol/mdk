# AGENTS.md - mdk

Repository-level rules and routing for coding agents. `README.md` is the human overview (what each crate is, how the
layers fit); don't duplicate it here.

The canonical protocol specification lives in `github.com/marmot-protocol/marmot`. This repo owns the Rust
implementation, its architecture notes, conformance fixtures, formal models, and diagnostics.

Nested `AGENTS.md` files add rules for their subtree. Read the nearest one before editing.

## MDK and host-app ownership

MDK owns shared product logic and authoritative state; White Noise Android is a
minimal display and Android platform layer. Follow [the host-app boundary](docs/marmot-architecture/overview/app-core-boundary.md#host-app-boundary)
before adding behavior or bindings.

## Where to go

| Task | Start here |
| --- | --- |
| Engine behavior | `crates/cgka-engine/AGENTS.md` (`src/`, `tests/` have their own) |
| Account-device runtime and session lifecycle | `crates/marmot-session/AGENTS.md` (`tests/` has its own) |
| Account homes, signing keys, secret storage | `crates/marmot-account/AGENTS.md` |
| Device pairing (the code exchange that links a new device) | `crates/marmot-pairing/AGENTS.md` |
| App runtime bridge | `crates/marmot-app/AGENTS.md` |
| App message Markdown display parsing | `crates/marmot-markdown/AGENTS.md` |
| Storage traits and shared types | `crates/traits/AGENTS.md` |
| Private file/dir/socket creation helpers | `crates/fs-private/AGENTS.md` |
| Encrypted per-file media store (format, file lifecycle) | `crates/media-store/AGENTS.md` |
| User directory (lookups, search, KeyPackage resolution, directory cache schema) | `crates/nostr-directory/AGENTS.md` |
| Diagnostics exporters (relay-telemetry OTLP, product analytics and consent state, performance recorder, audit delivery HTTP, collector dial safety) | `crates/marmot-observability/AGENTS.md` |
| SQLite storage | `crates/storage-sqlite/AGENTS.md` (`src/base/migrations/`, `src/protocol/openmls_storage/`, `src/protocol/storage/`, `src/protocol/storage/snapshots/` have their own) |
| Nostr transport adapter | `crates/transport-nostr-adapter/AGENTS.md` |
| Nostr relay plane (relay sessions, delivery, publish accounting, directory fetches) | `crates/transport-nostr/AGENTS.md` |
| Nostr transport peeler | `crates/transport-nostr-peeler/AGENTS.md` |
| Agent control protocol DTOs / framing | `crates/agent-control/AGENTS.md` |
| `wn-agent` connector daemon | `crates/agent-connector/AGENTS.md` |
| Host integrations / connector coexistence | `integrations/AGENTS.md` |
| Hermes gateway plugin | `integrations/hermes/marmot/AGENTS.md` (tests: `integrations/hermes/tests/marmot/AGENTS.md`) |
| OpenClaw channel plugin | `integrations/openclaw/marmot/AGENTS.md` |
| Shared terminal-harness runtime | `integrations/terminal-harness/AGENTS.md` |
| Claude Code / Codex / OpenCode / Pi / Goose harnesses | `integrations/{claude,codex,opencode,pi,goose}/marmot/AGENTS.md` |
| Forensic audit schema | `crates/marmot-forensics/AGENTS.md` |
| Production audit pipeline (White Noise audit receiver and reader in `internet-privacy/whitenoise-data`), investigating a group from audit records | `docs/marmot-architecture/audit-logging.md#downstream-whitenoise-data`; query with `.agents/skills/whitenoise-reader/SKILL.md` |
| App runtime UniFFI bindings | `crates/marmot-uniffi/AGENTS.md` |
| UniFFI async-export runtime macro | `crates/marmot-uniffi-macros/AGENTS.md` |
| App runtime C ABI bindings | `crates/marmot-c/AGENTS.md` |
| CLI / daemon surface | `crates/cli/AGENTS.md` |
| Multi-client harness / vectors | `crates/cgka-conformance-simulator/AGENTS.md` (`src/`, `tests/`, `vectors/` have their own) |
| Container/VM convergence campaigns | `crates/convergence-campaign-runner/AGENTS.md` |
| Architecture docs | `docs/AGENTS.md` and `docs/marmot-architecture/AGENTS.md` |
| Formal model | `formal/tamarin/AGENTS.md` |
| Formal verification method, proof coverage, and model-to-code correspondence | `.agents/skills/formal-verification/SKILL.md` |
| Runtime verification, acceptance journeys, and execution evidence | `.agents/skills/verify-mdk/SKILL.md` |
| Change impact, downstream contracts, and compatibility risks | `.agents/skills/blast-radius/SKILL.md` |
| Restate the last response in plain language | `.agents/skills/bro/SKILL.md` |
| Releases | `release.md` |
| Writing, reviewing, or pruning tests | `.agents/skills/test-audit/SKILL.md` |
| Landing a change (verify, review, PR, squash-merge) | `.agents/skills/land-change/SKILL.md` |
| Writing a PR description | `.agents/skills/gh-create-pr/SKILL.md` |

## Landing changes

Every change reaches `master` through a reviewed, signed squash PR; nobody pushes directly to `master` and there is
no merge queue. The shipping flow is:

1. **Local verification & review:** Run scoped checks plus the end-to-end smoke (`.agents/skills/land-change`), get two
   independent cross-model reviews (`.agents/skills/review-local`) until both recommend merge, and record three commit
   trailers on the final signed commit (which GitHub preserves in squash commits under `COMMIT_MESSAGES`, verified
   locally with `just pr-trailers-check`):
   - `Local-Checks: <commands run locally>`
   - `Local-Review: <seat-a> + <seat-b> merge @ <short-sha>` (or `human` / `exempt (<reason>)`)
   - `Release-Impact: none | patch | minor` — cross-checked against any `changelog.d/<slug>.md` fragments (`### Breaking changes` requires `minor`; non-breaking user-facing fragments forbid `none`).
2. **Fast team PR gate (`Required CI`):** Open a short PR (`.agents/skills/gh-create-pr`). Team PRs (same-repo branch
   by an author with `write`, `maintain`, or `admin` permission) run a ~1-minute static gate with zero Rust compile:
   verified commit signatures, `cargo fmt --all --check`, all static/contract gates, `cargo --locked audit`, and
   advisory commit-trailer checks. External/fork PRs, read-only org members, and `ci:full` PRs fail closed into the full
   `ci.yml` matrix on GitHub-hosted runners; `ci:apple` adds both macOS jobs (`ios-account-clippy`,
   `marmotkit-native-host`) to a team PR regardless of changed paths. When Meltdown Mode sets the `tree-state` branch
   (`state.json` = `"red"`), `Required CI` fails at check time unless labelled `tree-fix` or `revert` (PRs whose
   `Required CI` already passed before the freeze are not retroactively invalidated by GitHub, so step 3 /
   `land-change` Step 7 also checks `origin/tree-state:state.json` before merging, and PRs blocked during a freeze
   need `Re-run all jobs` once `tree-state` returns to `"green"`).
3. **Squash-merge (only when told to land):** `master` requires `Required CI`, any `CODEOWNERS` approvals, and a branch
   up to date with `master`, so a ready PR can merge a minute after it opens: finish step 1 before opening it.
   Agents stop at a green PR unless the user told them to land it (`.agents/skills/land-change`). Unless labelled
   `tree-fix` or `revert`, confirm `origin/tree-state:state.json` is `"green"` right before merging, confirm
   `headRefOid` matches the reviewed head, and run `gh pr merge <pr> --squash --match-head-commit <sha>`; never
   `--auto`, `--admin`, or a direct push.
4. **Post-merge `Canary`, Bisect Agent & daily SemVer RCs:** Bare-metal Linux Canary on `mdk-ci-1` verifies `master`
   every 30 minutes (`fast-ci`, `cargo-audit`, `wasm-check`, `android-check`, `workspace-nextest`, `simulator-smoke`)
   and advances the protected `canary` branch; hourly `.github/workflows/canary.yml` runs the full cross-platform
   matrix (de-sharded to 6 workspace shards plus Android, WASM, C bindings, macOS, Windows, Tamarin, and conditional
   `bindings-profile.yml` under `macos-packaging` concurrency) whenever `master` moves. The revert-only Bisect Agent
   (`scripts/bisect_agent/`) classifies failures into 5 buckets (infra, known flake, new intermittent, unreproducible,
   deterministic regression), bisects deterministic failures to open clean signed `revert` PRs, and freezes
   `tree-state` (`red`) on tangled/failed reverts, unisolatable failures, or 2 consecutive unreproducible reds
   (auto-clearing to `green` on recovery). Daily `.github/workflows/rc-releases.yml` builds SemVer Release Candidates
   (`0.X.(Y+1)-rc.N` / `0.(X+1).0-rc.N`) strictly from the verified `canary` branch tip, gated on `simulator-nightly` +
   `convergence-hardening` + all three tracks, and publishes `rc/latest.json` + `rc/signature_delta.json` on `rc-meta`.
   Promote a verified RC to a formal Stable cohort with `just promote-rc <rc>` (`.github/workflows/promote-release.yml`).

## Documentation

- `README.md` files are for humans: what it is, how to use it, where to go next. `AGENTS.md` files are for agents:
  boundaries, invariants, code map, editing rules, verification. Keep agent directives out of READMEs and tutorials
  out of `AGENTS.md`; link instead of duplicating.
- When you add, rename, or remove a crate, binary, `just` recipe, or user-facing command, update the root `README.md`
  crate map and the affected crate README in the same change.
- Record a user-facing change as a new fragment file, `changelog.d/<slug>.md`, beside the `CHANGELOG.md` it belongs
  to (repository root or crate). Never edit a `CHANGELOG.md` to add an entry: concurrent PRs that add lines at the same
  spot conflict on merge. A fragment holds one or more `### <Section>` headings
  (`Breaking changes`, `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`), each followed by its
  entries, and its kebab-case slug names the change. To revise an unreleased entry, edit or delete its fragment.
  The release metadata PR folds the fragments in with `just changelog-release <version>`. Run `just changelog-gate`
  when you add or edit one.
- Do not add `CLAUDE.md` files or `CLAUDE.md` symlinks; `AGENTS.md` is the single agent-instruction file.
- Shared agent skills live in `.agents/skills/<name>/SKILL.md`, which Codex and Cursor read. Claude Code reads only
  `.claude/skills`, so that path is a symlink to `../.agents/skills`; keep it, and add skills to `.agents/skills` only.

## Invariants

- Keep the engine generic over `S: cgka_traits::StorageProvider`.
- Keep transport-specific code out of `crates/cgka-engine`, `crates/traits`, and storage crates.
- Keep SQLite persistence one database per Marmot account-device identity.
- Keep Tamarin model names, Rust test names, and vector names easy to grep across layers.
- Keep protocol principles and app-component documents implementation-neutral in `marmot-protocol/marmot`. Local engine,
  storage, queue, and diagnostic notes belong in architecture docs or crate docs here.
- Keep MLS group ids distinct from transport routing ids. `GroupId` is opaque MLS group id bytes; OpenMLS-generated ids
  are 16 bytes today, but spec surfaces that bind raw MLS group ids length-prefix them because they are variable-length.
  `nostr_group_id` / `transport_group_id` is the 32-byte Nostr routing handle. Do not apply the 32-byte Nostr route-id
  rule to `GroupId` validation, FFI parsing, storage lookups, or CLI/app group-id filters.
- Keep tracing/logging privacy-safe: explicit crate/module `target` and `method` fields, aggregate values only, and no
  account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext, plaintext, or key material. See
  `docs/marmot-architecture/overview/observability.md`.
- Create local files, sockets, and databases restrictive-by-construction via `crates/fs-private` (or equivalent
  posture with an on-disk mode test), and release their file locks explicitly before a host suspends
  (`MarmotAppRuntime::shutdown_and_close`); see `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Route every outbound connection through the host-safety dial discipline: validate each resolved address with
  `cgka_traits::app_components::reject_non_public_ip`, pin the validated address, choose TLS trust from config (never a
  resolved IP), apply a connect timeout, and gate loopback behind an explicit dev flag. See
  `docs/marmot-architecture/overview/dial-safety.md`.
- Never dial or adopt hosts on the centralized retired-relay denylist. Retired
  relays must not be used for discovery, bootstrap, examples, or runtime
  traffic; keep exact endpoint literals confined to the denylist and rejection
  regression tests.
- Keep multi-step state changes torn-write-free: validate before mutating, compensate every applied step on the error
  path, record intent before external side effects, and never confirm work that reached no one. See
  `docs/marmot-architecture/overview/multi-step-state-changes.md`.
- Treat workspace and conformance-fixture version bumps as manual release operations. Never change the root workspace
  version, workspace package versions in `Cargo.lock`, or vector `conformance_version` values during feature, fix,
  binding, or review-feedback work unless the user explicitly requests that version bump. The post-release move of
  master to the next `X.Y.0-dev` is one of those release operations; see `release.md#development-versions`.
- Keep binding READMEs and complete method references current with API changes; run `just binding-docs-gate`.
  Starting with 0.10.2, every release requires concise `docs/release/<version>.md` notes and a detailed
  `docs/integration/<version>.md` companion, indexed and linked both ways. Follow `release.md#release-documentation`:
  distinguish required changes, new defaults, optional adoption and automatic fixes; preserve supported lower-level
  APIs and exact artifact provenance. Post-tag documentation uses a supplement commit, never a moved release tag.
- Title GitHub Releases with the version first so release lists group by cohort: whole-workspace `v<version> - MDK`,
  WN Agent `v<version> - wn-agent`, and MarmotKit `v<version> - MarmotKit`.
- Prefer `just release-all <version>` for a full MDK/WN Agent/MarmotKit cohort release, or
  `just release-all-draft <version>` when releases should stay draft for manual publication.
- Sign every commit before pushing. This repository accepts only cryptographically signed commits;
  configure Git SSH signing (or another accepted signing method) and verify the signature locally.

## Verification

Local verification proves your change before merge, and post-merge `Canary` runs continuously verify `master` across
the full suite. Keep local runs scoped to your change: several agents usually build on the same machine, so
workspace-wide builds and suites run locally only when a rule below calls for one. On team pull requests, `Required CI`
runs a ~1-minute static gate (verified commit signatures, `cargo fmt --check`, static/contract gates, `cargo audit`,
and advisory commit-trailer checks) with zero Rust compile. External/fork pull requests and PRs labelled `ci:full` run
the full `ci.yml` matrix on GitHub-hosted runners; `ci:apple` adds both macOS jobs on a team PR regardless of changed
paths. Master pushes only refresh CI's Rust caches, and only when a dependency or toolchain input changes.

While iterating, run only the test you are working on. Before each push, run once:

```sh
cargo fmt --all
cargo clippy -p <crate> --all-targets --locked -- -D warnings                  # each crate you changed, default features
cargo clippy -p <crate> --all-targets --all-features --locked -- -D warnings   # each crate you changed, all features
just dependents-nextest                                                        # changed crates and every crate depending on one
```

- `just dependents-nextest` runs the full suites of every crate you changed and of every crate that depends on one,
  with the Canary's test features, so a change to a lower crate cannot break `marmot-session` or `marmot-app` unseen.
  Run it once per push, one at a time per machine. Also run any feature-gated suite the nearest `AGENTS.md`
  Verification section names.
- Stress every test you added or edited, alone and without retries: `just flake-stress <crate> 'test(=<name>)' 5`.
- Run the `just` gates the nearest `AGENTS.md` names for the files you touched. Outside crates:
  `.github/workflows/` and CI scripts → `just ci-path-classifier-gate`; installers and install docs →
  `just agent-install-docs-gate` and `just install-example-sha256-gate`; new or renamed paths → `just naming-gate`.
- When CI fails, reproduce the failing test by name (`cargo nextest run -p <crate> -E 'test(=<name>)'`) instead of
  rerunning a suite or the whole gate.

Widen only for these changes:

- A `pub` item other crates use (type, field, enum variant, trait, signature, feature): run CI's lint once,
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`. It compiles every dependent and the
  feature-gated test targets (`test-crash-hooks`, `test-policy-overrides`) that default builds skip.
- Shared build inputs (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, `Justfile`, `vendor/`) or
  `.github/workflows/`: `just fast-ci` once.
- Convergence, delivery, branch-selection, or multi-client behavior: `just simulator-smoke` (the Canary smoke
  selection).
- Formal model: `just tamarin`.

Do not run `just ci`, `just test`, `cargo test --workspace`, `--features conformance-slow`, benchmarks, or the
convergence lanes locally unless the user asks; post-merge `Canary` and daily `RC` cover the full matrix. `just fast-ci`
is fmt, the static gates, and CI's two workspace clippy passes, so it is not a per-push default.

Exception: for an initial cohort-release PR limited to version fields, workspace package versions in `Cargo.lock`,
vector `conformance_version` values, changelogs, release/integration documentation, README/install version pins, and
other release metadata, run only `just release-pr-preflight <version>`, open the PR with the `ci:full` label
(re-running all jobs if CI started before the label was applied), and confirm the full GitHub CI matrix passes on the
current head before merging. Do not run `just fast-ci`, `just test`, `just ci`, Tamarin, benchmarks, binding bundle
builds, or artifact builds before opening that PR. If preparing the release exposes an implementation or workflow
defect, fix it in a separate PR with the normal targeted verification instead of expanding the metadata PR. After the
metadata PR is merged and required CI succeeds, run `just release-all <version>` to build and publish the cohort.

The install-example gate renders all six installer `--help` surfaces and checks
release guidance plus workflow-generated notes for download, sibling `.sha256`
verification (`shasum` or `sha256sum`), then local execution. It also rejects
new download-to-shell examples in tracked Markdown, shell, and workflow files.
