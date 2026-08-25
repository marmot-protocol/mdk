# MDK Release Guide

This file is the release checklist for MDK itself, generated MarmotKit bindings used by app repos, and
repository-built binaries such as WN Agent.

## Release Tracks

MDK uses one workspace version as the compatibility cohort and separate tag prefixes for each artifact track.
That keeps tightly coupled crates, bindings, and binaries easy to reason about while still letting us publish only the
artifact that changed.

Current tracks:

- Whole-workspace releases use tags like `v0.9.0`. These identify a versioned source snapshot of the protocol draft,
  Rust workspace, CLI, daemon, TUI, app runtime, storage, transports, agent crates, and binding source crate. MDK
  `0.9.0` is the unifying workspace bump above the previous `0.8.0` release.
- WN Agent releases use tags like `wn-agent-v0.9.0`. These publish the `wn-agent` connector binary plus adapter and
  harness install assets, including Hermes, OpenClaw, and OpenCode.
- MarmotKit binding releases use tags like `marmotkit-v0.9.0`. These build generated app-consumable binding bundles
  from `crates/marmot-uniffi` and attach them to a GitHub Release.

Future binary or package tracks should follow the same shape, for example `quic-broker-v0.9.0` or `wn-cli-v0.9.0`, only
when those artifacts become independently consumed release surfaces.

When multiple tracks correspond to the same source snapshot, create the tags on the same commit:

```sh
git tag -a v0.9.0 -m "mdk v0.9.0"
git tag -a wn-agent-v0.9.0 -m "WN Agent v0.9.0"
git tag -a marmotkit-v0.9.0 -m "MarmotKit v0.9.0"
git push origin v0.9.0 wn-agent-v0.9.0 marmotkit-v0.9.0
```

The workspace is not published to crates.io today. The root `Cargo.toml` has `publish = false`, and the crates depend
on each other through workspace paths. Treat Git tags and GitHub Releases as the release surface unless that changes.

## Version Rules

Use the root `Cargo.toml` workspace version as the release version for the Rust workspace, WN Agent, CLI, daemon, TUI,
app runtime, and generated bindings:

```toml
[workspace.package]
version = "0.9.0"
```

Use the same version number in:

- `v<version>` for the whole workspace;
- `wn-agent-v<version>` for WN Agent binary and adapter-install releases;
- `marmotkit-v<version>` for generated app binding bundles;
- `crates/cli/CHANGELOG.md` for CLI-visible changes.

The tag prefix names the artifact track. The numeric version names the compatibility cohort. It is fine for one track to
skip versions when it has no changed artifact to publish. Do not reuse the same track/version tag for a different commit.

Title GitHub Releases with the version first so release lists group artifacts by compatibility cohort:

- whole-workspace source releases: `v0.9.3 - MDK`;
- WN Agent releases: `v0.9.3 - wn-agent`;
- MarmotKit binding releases: `v0.9.3 - MarmotKit`.

For a full cohort release across all three current tracks, use the coordinator:

```sh
just release-all 0.9.3
```

This creates `v<version>`, `wn-agent-v<version>`, and `marmotkit-v<version>` on the same `origin/master` commit,
creates the MDK source GitHub Release with generated notes starting from the previous `v*` tag, pushes the artifact
tags, waits for the WN Agent and MarmotKit release workflows, verifies expected release metadata/assets, and marks the
MDK source release as Latest.

To stage the same cohort for manual review, leave every GitHub Release draft:

```sh
just release-all-draft 0.9.3
```

Draft mode creates draft release objects after each tag is pushed. The WN Agent and MarmotKit workflows upload their
assets into those draft releases and leave them draft, so a human can review and publish them from GitHub.

For a no-op rehearsal:

```sh
just release-all-dry-run 0.9.3
```

Use a new version when public behavior changes. That includes:

- UniFFI records, enums, object methods, async methods, or error variants;
- app runtime behavior that iOS or Android depends on;
- WN Agent, CLI, daemon, or TUI commands and JSON output;
- agent-control protocol, adapter/plugin contract, installer, or config behavior;
- protocol, transport, storage, or vector changes that downstream users need to pin.

Before `1.0.0`, treat `0.<minor>.0` as the breaking-compatibility line and `0.<minor>.<patch>` as the compatible bugfix
or packaging line. Avoid `0.0.x` releases unless every update is intentionally a breaking experiment.

Each release artifact should include a manifest recording the source commit, workspace version, release tag, artifact
version, `Cargo.lock` hash when relevant, toolchain version, and package contents. Add explicit protocol or ABI fields
to manifests when downstream compatibility depends on more than the workspace version.

## Preflight For Any Release

Start from a clean checkout at the commit you intend to release:

```sh
git status --short --branch
git fetch origin
```

Confirm the version and release notes:

```sh
rg -n '^version = ' Cargo.toml
sed -n '1,120p' crates/cli/CHANGELOG.md
```

Run the normal workspace checks:

```sh
just fmt-check
just check
just clippy
just test
```

Run the formal model when the release includes protocol, engine, convergence, vector, or Tamarin-facing changes:

```sh
just tamarin
```

Run focused binding checks before any MarmotKit release:

```sh
cargo test -p marmot-uniffi
```

If app-facing bindings changed, also build the local bundles before tagging when the needed host toolchains are
available:

```sh
./crates/marmot-uniffi/xcframework.sh
./crates/marmot-uniffi/kotlin-bindings.sh
```

The binding build scripts source `crates/marmot-uniffi/marmotkit-endpoints.env` from the workflow builder checkout so
production MarmotKit artifacts embed one platform-consistent set of public audit-log and OTLP route defaults. The
canonical Rust release profile comes from that builder checkout as well; API-coupled inputs such as the Cargo
workspace, UniFFI configuration, and Kotlin support files come from the packaged source checkout. Override
`MARMOT_AUDIT_LOG_TRACKER_ENDPOINT` or `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT` in the environment only for staging or
local collector builds. Bearer tokens are not compiled into MarmotKit; apps supply them at runtime.

The GitHub workflow repeats the release builds on clean runners. Local builds catch drift earlier.

## Storage-Format Changes

For a release that adds a `storage-sqlite` migration or changes an opaque
storage artifact:

1. Link the format definition and compatibility evidence from
   `docs/marmot-architecture/storage-format-v2.md` in the release notes.
2. Verify an older fixture opens and upgrades once, a current fixture reopens
   without rewriting, and the prior binary refuses the new migration before
   reading or writing account tables. The current migration runner's downgrade
   guard must remain a typed `StorageError::UnsupportedSchemaVersion`; a pinned
   previously shipped binary may retain its older error wrapper, but it must
   still refuse before application-table access.
3. Run crash/failure-injection tests at every multi-row transformation or
   artifact replacement boundary. Schema migrations are transactional;
   background promotion work must additionally be row-idempotent and bounded.
4. State explicitly that downgrade across the migration is unsupported. The
   remedies are to re-upgrade or restore a pre-upgrade account database/export;
   never advise manually removing migration rows.
5. Recommend a pre-upgrade backup/export for the migration-47 cohort. Although
   it preserves legacy row bytes and defers per-row format promotion, its
   transactional table rebuild physically copies the complete message history.
   Before promoting the release cohort, capture the stable `MDK_BENCH` output
   from a representative large-account run:

   ```sh
   MDK_STORAGE_OPS_ROWS=2048 just bench-storage-upgrade
   ```

   The 2026-08-14 baseline peaked at 4.01 times the starting database footprint
   and needed 3.01 times that footprint as additional temporary space. Release
   notes should require at least 3.25 times the account database size free
   before upgrade, report the newly measured duration, peak footprint, and
   maximum 32-row batch latency, and explain that the estimate must be refreshed
   if the format or journal policy changes.
6. Do not run `VACUUM` during automatic account open. If page reclamation is
   useful, expose it as explicit keyed-connection maintenance and report its
   expected duration and temporary free-space requirement.
7. Ship the change as one synchronized cohort via `just release-all <version>`
   so MDK, wn-agent, and MarmotKit agree on the database boundary. Call out
   migration 47, unsupported downgrade, the backup remedy, and gradual
   post-readiness promotion in every applicable release note. Workspace and
   package version changes remain a separate manual release operation.

Storage migrations do not require a workspace version bump during feature
development. The eventual release version remains a manual release operation.

Before pushing, run `just fast-ci`. Let GitHub CI run the full `just ci` test
matrix.

## Whole-Workspace Release

Use this for a versioned MDK source/library release.

1. Update the workspace version in `Cargo.toml`.
2. Move relevant `crates/cli/CHANGELOG.md` entries out of `Unreleased`.
3. Update docs that describe changed public behavior.
4. Run the preflight checks above.
5. Create an annotated tag:

   ```sh
   git tag -a v0.9.0 -m "mdk v0.9.0"
   git push origin v0.9.0
   ```

6. Create or update the GitHub Release for `v0.9.0` on the MDK repo releases page.
7. Include release notes that name the source commit, major user-visible changes, and any migration notes.

Until a dedicated whole-workspace release workflow exists, the whole-workspace GitHub Release is a source release. The
GitHub-generated source archives are the downloadable artifacts.

## WN Agent Release

Use this for the White Noise agent connector entry point. The release publishes `wn-agent` binaries for supported
platforms plus adapter/harness install assets: the Hermes Marmot plugin + `install-hermes-marmot.sh`, the OpenClaw
Marmot channel plugin + `install-openclaw-marmot.sh`, the `wn-codex` harness +
`install-codex-marmot.sh`, the `wn-opencode` harness +
`install-opencode-marmot.sh`, and the `wn-pi` harness + `install-pi-marmot.sh`.

The workflow lives at:

```text
.github/workflows/wn-agent-binaries.yml
```

Pull requests, master pushes, and manual workflow runs build validation artifacts only. Publishing happens only when a
tag matching `wn-agent-v*` is pushed. The workflow validates version-like tags such as `wn-agent-v0.9.0` and requires
the tag version to match the root workspace version in `Cargo.toml`.

Before a WN Agent release, run the normal preflight plus:

```sh
cargo test -p agent-connector
cargo test -p marmot-terminal-harness
cargo test -p wn-codex
cargo test -p wn-opencode
cargo test -p wn-pi
sender_hex="$(awk 'BEGIN { for (i = 0; i < 32; i++) printf "11" }')"
bash scripts/install-hermes-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --allow-user "$sender_hex"
bash scripts/install-openclaw-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex"
bash scripts/install-codex-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --codex-bin /bin/echo
bash scripts/install-opencode-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --opencode-bin /bin/echo
bash scripts/install-pi-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --pi-bin /bin/echo
```

Bridge and control logs for all terminal harnesses use the
`marmot_terminal_harness` tracing target. Include
`marmot_terminal_harness=debug` in `RUST_LOG`. The former `wn_opencode` target
no longer emits events, so existing filters that reference it must be updated.

The terminal-harness installer now keeps prompt senders separate from invite
authorization. Existing OpenCode automation must pass at least one explicit
`--allow-welcomer`; `WN_OPENCODE_ALLOWED_SENDERS_HEX` configures prompt senders
only and no longer satisfies the bootstrap welcomer requirement.

Cut the release tag from the current `origin/master` commit:

```sh
just release-wn-agent 0.9.3
```

For releases that should include the matching MDK source and MarmotKit tracks, prefer `just release-all 0.9.3` or
`just release-all-draft 0.9.3`.

For a dry run:

```sh
just release-wn-agent-dry-run 0.9.3
```

The helper checks that the workspace version matches, the working tree is clean, `HEAD` matches `origin/master`, and the
`wn-agent-v<version>` tag does not already exist locally or remotely. Pushing the tag starts the GitHub release workflow.

The release job creates these assets:

- `wn-agent-linux-x86_64-<version>.tar.gz`
- `wn-agent-linux-x86_64-<version>.tar.gz.sha256`
- `wn-agent-linux-aarch64-<version>.tar.gz`
- `wn-agent-linux-aarch64-<version>.tar.gz.sha256`
- `wn-agent-darwin-aarch64-<version>.tar.gz`
- `wn-agent-darwin-aarch64-<version>.tar.gz.sha256`
- `wn-agent-darwin-x86_64-<version>.tar.gz`
- `wn-agent-darwin-x86_64-<version>.tar.gz.sha256`
- `wn-codex-linux-x86_64-<version>.tar.gz`
- `wn-codex-linux-x86_64-<version>.tar.gz.sha256`
- `wn-codex-linux-aarch64-<version>.tar.gz`
- `wn-codex-linux-aarch64-<version>.tar.gz.sha256`
- `wn-codex-darwin-aarch64-<version>.tar.gz`
- `wn-codex-darwin-aarch64-<version>.tar.gz.sha256`
- `wn-codex-darwin-x86_64-<version>.tar.gz`
- `wn-codex-darwin-x86_64-<version>.tar.gz.sha256`
- `wn-opencode-linux-x86_64-<version>.tar.gz`
- `wn-opencode-linux-x86_64-<version>.tar.gz.sha256`
- `wn-opencode-linux-aarch64-<version>.tar.gz`
- `wn-opencode-linux-aarch64-<version>.tar.gz.sha256`
- `wn-opencode-darwin-aarch64-<version>.tar.gz`
- `wn-opencode-darwin-aarch64-<version>.tar.gz.sha256`
- `wn-opencode-darwin-x86_64-<version>.tar.gz`
- `wn-opencode-darwin-x86_64-<version>.tar.gz.sha256`
- `wn-pi-linux-x86_64-<version>.tar.gz`
- `wn-pi-linux-x86_64-<version>.tar.gz.sha256`
- `wn-pi-linux-aarch64-<version>.tar.gz`
- `wn-pi-linux-aarch64-<version>.tar.gz.sha256`
- `wn-pi-darwin-aarch64-<version>.tar.gz`
- `wn-pi-darwin-aarch64-<version>.tar.gz.sha256`
- `wn-pi-darwin-x86_64-<version>.tar.gz`
- `wn-pi-darwin-x86_64-<version>.tar.gz.sha256`
- `hermes-marmot-plugin-<version>.tar.gz`
- `hermes-marmot-plugin-<version>.tar.gz.sha256`
- `openclaw-marmot-plugin-<version>.tgz`
- `openclaw-marmot-plugin-<version>.tgz.sha256`
- `install-hermes-marmot.sh`
- `install-hermes-marmot.sh.sha256`
- `install-openclaw-marmot.sh`
- `install-openclaw-marmot.sh.sha256`
- `install-codex-marmot.sh`
- `install-codex-marmot.sh.sha256`
- `install-opencode-marmot.sh`
- `install-opencode-marmot.sh.sha256`
- `install-pi-marmot.sh`
- `install-pi-marmot.sh.sha256`

Each binary/plugin tarball carries a `manifest.json` recording the release tag, artifact version, source commit, and
workspace version (the OpenClaw tarball's `package.json` version is also stamped to the cohort version at release time).

The installer assets are generated during the release and default to their own immutable `wn-agent-v<version>` release
tag and `<version>` asset suffix. The mutable `wn-agent-latest` release is a rolling convenience alias, not an
authoritative pin; repeatable installs use immutable `wn-agent-v<version>` tags. A verified install for the current
workspace release looks like:

```sh
(
set -eu
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.15"

install_verified() (
  set -eu
  installer_url="$1"
  checksum_url="$2"
  shift 2
  installer_script="${installer_url##*/}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' 0 HUP INT TERM
  curl -fsSL "$installer_url" -o "$tmpdir/$installer_script"
  curl -fsSL "$checksum_url" -o "$tmpdir/$installer_script.sha256"
  if command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && shasum -a 256 -c "$installer_script.sha256")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && sha256sum -c "$installer_script.sha256")
  else
    echo "error: need shasum or sha256sum to verify the installer" >&2
    exit 1
  fi
  bash "$tmpdir/$installer_script" "$@"
)

# Hermes gateway
install_verified "$base_url/install-hermes-marmot.sh" "$base_url/install-hermes-marmot.sh.sha256"
# OpenClaw gateway
install_verified "$base_url/install-openclaw-marmot.sh" "$base_url/install-openclaw-marmot.sh.sha256"
# Codex terminal harness
install_verified "$base_url/install-codex-marmot.sh" "$base_url/install-codex-marmot.sh.sha256"
# OpenCode terminal harness
install_verified "$base_url/install-opencode-marmot.sh" "$base_url/install-opencode-marmot.sh.sha256"
# Pi terminal harness
install_verified "$base_url/install-pi-marmot.sh" "$base_url/install-pi-marmot.sh.sha256"
)
```

Change the immutable `wn-agent-v<version>` release URL when you need to pin a different release for repeatable testing or
bug reports. Keep each installer URL paired with its sibling `.sha256` URL and execute only the verified local copy.

These verified installers perform full setup by default: they install `wn-agent`, install/enable the matching gateway
plugin or harness binary, start same-user services where supported, bootstrap or reuse the default connector-specific
Marmot agent home, and patch only the Marmot-specific gateway config when a gateway is involved. Use `--no-service`,
`--no-start-wn-agent`, `--no-configure-hermes`, `--no-configure-openclaw`, or `--no-start-wn-opencode` when you need a
partial/manual install. Terminal-harness installers also accept the matching
`--no-start-wn-codex` or `--no-start-wn-pi` option.

## MarmotKit Binding Release

Use this when app repos need pinned generated bindings instead of a local MDK checkout.

The workflow lives at:

```text
.github/workflows/bindings.yaml
```

It runs when a tag matching `marmotkit-v*` is pushed. The workflow validates version-like tags such as
`marmotkit-v0.9.0`, builds the iOS, macOS, and Android binding bundles, and creates the matching immutable GitHub
Release. It can also be dispatched with a full commit SHA reachable from `master` to create an immutable iOS, macOS,
and Android snapshot.

Create the tag:

```sh
git tag -a marmotkit-v0.9.0 -m "MarmotKit v0.9.0"
git push origin marmotkit-v0.9.0
```

For releases that should include the matching MDK source and WN Agent tracks, prefer `just release-all 0.9.3` or
`just release-all-draft 0.9.3`.

The release job creates these assets:

- `MarmotKitFFI-<version>.xcframework.zip` (iOS)
- `MarmotKitFFI-<version>.xcframework.zip.sha256`
- `MarmotKitFFI-<version>.xcframework.zip.swiftpm-checksum`
- `marmotkit-ios-<version>.manifest.json`
- `marmotkit-ios-<version>.checksums.txt`
- `marmotkit-ios-<version>.zip`
- `marmotkit-ios-<version>.zip.sha256`
- `MarmotKitFFI-macos-<version>.xcframework.zip` (macOS, Apple Silicon)
- `MarmotKitFFI-macos-<version>.xcframework.zip.sha256`
- `MarmotKitFFI-macos-<version>.xcframework.zip.swiftpm-checksum`
- `marmotkit-macos-<version>.manifest.json`
- `marmotkit-macos-<version>.checksums.txt`
- `marmotkit-macos-<version>.zip`
- `marmotkit-macos-<version>.zip.sha256`
- `MarmotKit-<version>.swift` (shared by iOS and macOS)
- `marmotkit-android-<version>.zip`
- `marmotkit-android-<version>.zip.sha256`

The generated Swift binding is platform-independent, so it is published exactly once, by the iOS job. There is no
`MarmotKit-macos-<version>.swift`; macOS consumers use the same `MarmotKit-<version>.swift` from the same release.
Publishing fails if the iOS and macOS jobs ever generate different Swift from one source SHA.

Snapshot assets use `snapshot-<full-sha>` in place of `<version>` and are published under the exact
`marmotkit-snapshot-<full-sha>` release tag. The binary-only ZIP contains `MarmotKit.xcframework` at its archive root
for SwiftPM. Android snapshots publish `marmotkit-android-snapshot-<full-sha>.zip` and its sibling `.sha256` under the
same release tag. See `crates/marmot-uniffi/DISTRIBUTION.md` for exact URLs and consumer examples.

The iOS zip contains:

- `MarmotKit.xcframework`
- `MarmotKit.swift`
- `manifest.json`

The macOS zip contains:

- `MarmotKit.xcframework`
- `MarmotKit.swift`
- `manifest.json`

The Android zip contains:

- `kotlin/dev/ipf/marmotkit/marmot_uniffi.kt`
- `kotlin/dev/ipf/marmotkit/MarmotAndroid.kt`
- `kotlin/io/crates/keyring/Keyring.kt`
- `jniLibs/<abi>/libmarmot_uniffi.so` for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`
- `manifest.json`

Each manifest records the release identifier, exact source commit, workflow builder commit, workspace version,
`Cargo.lock` hash, and Rust toolchain versions. Apple manifests also record enabled features, targets, deployment
target, effective release profile, and artifact hashes. App repos must pin an exact tag, update generated source and
native libraries together, and verify the ordinary SHA-256 (plus SwiftPM checksum for Apple binaries). Existing
release assets and snapshot tags are never overwritten.

## App Repo Consumption

App repos should pin an exact formal MarmotKit tag or SHA-addressed snapshot, verify its published checksums, and stage
the generated source and native libraries into ignored build inputs or another repository-approved generated-artifact
location. Never mix generated source and native libraries from different release identifiers.

iOS expects the staged equivalent of:

```text
Vendored/MarmotKit/MarmotKit.xcframework
Vendored/MarmotKit/Sources/MarmotKit/MarmotKit.swift
```

Android expects the staged equivalent of:

```text
app/src/main/java/dev/ipf/marmotkit/marmot_uniffi.kt
app/src/main/java/dev/ipf/marmotkit/MarmotAndroid.kt
app/src/main/java/io/crates/keyring/Keyring.kt
app/src/main/jniLibs/<abi>/libmarmot_uniffi.so
```

After updating an app repo, run that app's normal compile and smoke checks. Binding generation passing in MDK
does not prove the app has adapted to every public API change.

## CLI And Homebrew Release

The CLI package is `wn-cli`; the installed binaries are:

- `wn`
- `wnd`

Before a CLI release, run:

```sh
cargo test -p wn-cli
cargo test -p marmot-app
```

Then smoke-test installed binaries from the release commit:

```sh
install_root="$(mktemp -d)"
cargo install --path crates/cli --locked --bins --root "$install_root" --force
"$install_root/bin/wn" --help
"$install_root/bin/wnd" --help
release_smoke_relay="${WN_RELEASE_SMOKE_RELAY:?set WN_RELEASE_SMOKE_RELAY to a disposable test relay}"
WN_HOME="$(mktemp -d)" WN_SECRET_STORE=file "$install_root/bin/wn" account create \
  --bootstrap-relays "$release_smoke_relay" \
  --default-relays "$release_smoke_relay" \
  --publish-missing-relay-lists
```

Homebrew release notes live in:

```text
docs/release/wn-homebrew.md
```

Use that checklist when updating `marmot-protocol/homebrew-tap`.

## Correcting A Release

If a tag points at the wrong commit and nobody should consume it, delete and recreate the tag before downstream repos or
testers pin it:

```sh
git tag -d wn-agent-v0.9.0
git push origin :refs/tags/wn-agent-v0.9.0
git tag -a wn-agent-v0.9.0 -m "WN Agent v0.9.0"
git push origin wn-agent-v0.9.0
```

If a release has already been consumed, create a new patch version instead.

The MarmotKit release job uploads and verifies assets while the release is still a draft, then publishes it. A failed
pre-publication run may be retried: the workflow deletes only its incomplete draft and starts again. If remote URL,
size, digest, SwiftPM checksum, or consumer validation fails after publication, do not replace the immutable assets.
Publish a new formal patch version or snapshot source SHA instead. Deleting an immutable release does not make its tag
name reusable.

## Current Limits

- The workspace is not published to crates.io.
- The whole-workspace release is tag- and source-archive-based.
- MarmotKit does not publish a Swift package manifest or Maven package. Its binary-target ZIP is SwiftPM-compatible.
- Android consumers still need the UniFFI Kotlin runtime dependencies required by the generated Kotlin file.
- The QUIC broker image has its own GHCR flow in `.github/workflows/quic-broker-image.yml`; it is not part of the
  MarmotKit binding release.
