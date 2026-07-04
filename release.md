# MDK Release Guide

This file is the release checklist for MDK itself, generated MarmotKit bindings used by app repos, and
repository-built binaries such as WN Agent.

## Release Tracks

MDK uses one workspace version as the compatibility cohort and separate tag prefixes for each artifact track.
That keeps tightly coupled crates, bindings, and binaries easy to reason about while still letting us publish only the
artifact that changed.

Current tracks:

- Whole-workspace releases use tags like `v0.1.0`. These identify a versioned source snapshot of the protocol draft,
  Rust workspace, CLI, daemon, TUI, app runtime, storage, transports, agent crates, and binding source crate.
- WN Agent releases use tags like `wn-agent-v0.2.0`. These publish the `wn-agent` connector binary plus adapter
  install assets, starting with the Hermes Marmot plugin and installer.
- MarmotKit binding releases use tags like `marmotkit-v0.1.0`. These build generated app-consumable binding bundles
  from `crates/marmot-uniffi` and attach them to a GitHub Release.

Future binary or package tracks should follow the same shape, for example `quic-broker-v0.1.0` or `wn-cli-v0.1.0`, only
when those artifacts become independently consumed release surfaces.

When multiple tracks correspond to the same source snapshot, create the tags on the same commit:

```sh
git tag -a v0.2.0 -m "mdk v0.2.0"
git tag -a wn-agent-v0.2.0 -m "WN Agent v0.2.0"
git tag -a marmotkit-v0.2.0 -m "MarmotKit v0.2.0"
git push origin v0.2.0 wn-agent-v0.2.0 marmotkit-v0.2.0
```

The workspace is not published to crates.io today. The root `Cargo.toml` has `publish = false`, and the crates depend
on each other through workspace paths. Treat Git tags and GitHub Releases as the release surface unless that changes.

## Version Rules

Use the root `Cargo.toml` workspace version as the release version for the Rust workspace, WN Agent, CLI, daemon, TUI,
app runtime, and generated bindings:

```toml
[workspace.package]
version = "0.2.0"
```

Use the same version number in:

- `v<version>` for the whole workspace;
- `wn-agent-v<version>` for WN Agent binary and adapter-install releases;
- `marmotkit-v<version>` for generated app binding bundles;
- `crates/cli/CHANGELOG.md` for CLI-visible changes.

The tag prefix names the artifact track. The numeric version names the compatibility cohort. It is fine for one track to
skip versions when it has no changed artifact to publish. Do not reuse the same track/version tag for a different commit.

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

The binding build scripts source `crates/marmot-uniffi/marmotkit-endpoints.env` so production MarmotKit artifacts embed
the public audit-log and OTLP route defaults. Override `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT` or
`MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT` in the environment only for staging or local collector builds. Bearer tokens are
not compiled into MarmotKit; apps supply them at runtime.

The GitHub workflow repeats the release builds on clean runners. Local builds catch drift earlier.

## Whole-Workspace Release

Use this for a versioned MDK source/library release.

1. Update the workspace version in `Cargo.toml`.
2. Move relevant `crates/cli/CHANGELOG.md` entries out of `Unreleased`.
3. Update docs that describe changed public behavior.
4. Run the preflight checks above.
5. Create an annotated tag:

   ```sh
   git tag -a v0.2.0 -m "mdk v0.2.0"
   git push origin v0.2.0
   ```

6. Create or update the GitHub Release for `v0.2.0` on the MDK repo releases page.
7. Include release notes that name the source commit, major user-visible changes, and any migration notes.

Until a dedicated whole-workspace release workflow exists, the whole-workspace GitHub Release is a source release. The
GitHub-generated source archives are the downloadable artifacts.

## WN Agent Release

Use this for the Dark Matter agent connector entry point. The release publishes `wn-agent` binaries for supported
platforms plus adapter install assets: the Hermes Marmot plugin + `install-hermes-marmot.sh`, and the OpenClaw Marmot
channel plugin + `install-openclaw-marmot.sh`. The track can grow other agent-system assets later.

The workflow lives at:

```text
.github/workflows/wn-agent-binaries.yml
```

Pull requests, master pushes, and manual workflow runs build validation artifacts only. Publishing happens only when a
tag matching `wn-agent-v*` is pushed. The workflow validates version-like tags such as `wn-agent-v0.2.0` and requires
the tag version to match the root workspace version in `Cargo.toml`.

Before a WN Agent release, run the normal preflight plus:

```sh
cargo test -p agent-connector
bash scripts/install-hermes-marmot.sh --dry-run
bash scripts/install-openclaw-marmot.sh --dry-run
```

Cut the release tag from the current `origin/master` commit:

```sh
just release-wn-agent 0.2.0
```

For a dry run:

```sh
just release-wn-agent-dry-run 0.2.0
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
- `hermes-marmot-plugin-<version>.tar.gz`
- `hermes-marmot-plugin-<version>.tar.gz.sha256`
- `openclaw-marmot-plugin-<version>.tgz`
- `openclaw-marmot-plugin-<version>.tgz.sha256`
- `install-hermes-marmot.sh`
- `install-openclaw-marmot.sh`

Each plugin tarball carries a `manifest.json` recording the release tag, artifact version, source commit, and workspace
version (the OpenClaw tarball's `package.json` version is also stamped to the cohort version at release time).

The installer assets are generated during the release and default to their own `wn-agent-v<version>` release tag and
`<version>` asset suffix. A release install looks like:

```sh
# Hermes gateway
curl -fsSL https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.2.0/install-hermes-marmot.sh | bash
# OpenClaw gateway
curl -fsSL https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.2.0/install-openclaw-marmot.sh | bash
```

## MarmotKit Binding Release

Use this when app repos need pinned generated bindings instead of a local MDK checkout.

The workflow lives at:

```text
.github/workflows/bindings.yaml
```

It runs only when a tag matching `marmotkit-v*` is pushed. The workflow validates version-like tags such as
`marmotkit-v0.2.0`, builds both binding bundles, and creates or updates the matching GitHub Release.

Create the tag:

```sh
git tag -a marmotkit-v0.2.0 -m "MarmotKit v0.2.0"
git push origin marmotkit-v0.2.0
```

The release job creates these assets:

- `marmotkit-ios-<version>.zip`
- `marmotkit-ios-<version>.zip.sha256`
- `marmotkit-android-<version>.zip`
- `marmotkit-android-<version>.zip.sha256`

The iOS zip contains:

- `MarmotKit.xcframework`
- `MarmotKit.swift`
- `manifest.json`

The Android zip contains:

- `kotlin/dev/ipf/marmotkit/marmot_uniffi.kt`
- `jniLibs/<abi>/libmarmot_uniffi.so` for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`
- `manifest.json`

Each manifest records the release tag, source commit, workspace version, `Cargo.lock` hash, Rust toolchain versions,
and package contents. App repos should pin a tag and verify the `.sha256` file before vendoring the bundle.

## App Repo Consumption

For now, app repos should download a versioned MarmotKit release asset and vendor the generated files into their current
checked-in binding locations.

iOS expects the equivalent of:

```text
Vendored/MarmotKit/MarmotKit.xcframework
Vendored/MarmotKit/Sources/MarmotKit/MarmotKit.swift
```

Android expects the equivalent of:

```text
app/src/main/java/dev/ipf/marmotkit/marmot_uniffi.kt
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
WN_HOME="$(mktemp -d)" WN_SECRET_STORE=file "$install_root/bin/wn" account create
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
git tag -d wn-agent-v0.2.0
git push origin :refs/tags/wn-agent-v0.2.0
git tag -a wn-agent-v0.2.0 -m "WN Agent v0.2.0"
git push origin wn-agent-v0.2.0
```

If a release has already been consumed, create a new patch version instead.

If the workflow succeeds but an uploaded asset is wrong, rerun the workflow from the same tag only when the source commit
is correct and the failure was packaging-only. The release job uploads assets with `--clobber`, so a rerun can replace
assets on the same GitHub Release.

## Current Limits

- The workspace is not published to crates.io.
- The whole-workspace release is tag- and source-archive-based.
- MarmotKit releases are zipped generated files, not SwiftPM or Maven packages.
- Android consumers still need the UniFFI Kotlin runtime dependencies required by the generated Kotlin file.
- The QUIC broker image has its own GHCR flow in `.github/workflows/quic-broker-image.yml`; it is not part of the
  MarmotKit binding release.
