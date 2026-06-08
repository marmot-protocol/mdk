# Darkmatter Release Guide

This file is the release checklist for Darkmatter itself and for generated MarmotKit bindings used by app repos.

## Release Tracks

Darkmatter currently has two versioned release tracks:

- Whole-workspace releases use tags like `v0.1.0`. These identify a versioned source snapshot of the protocol draft,
  Rust workspace, CLI, daemon, TUI, app runtime, storage, transports, and binding source crate.
- MarmotKit binding releases use tags like `marmotkit-v0.1.0`. These build generated app-consumable binding bundles
  from `crates/marmot-uniffi` and attach them to a GitHub Release.

When a binding release corresponds to a whole-workspace release, create both tags on the same commit:

```sh
git tag -a v0.1.0 -m "darkmatter v0.1.0"
git tag -a marmotkit-v0.1.0 -m "MarmotKit v0.1.0"
git push origin v0.1.0 marmotkit-v0.1.0
```

The workspace is not published to crates.io today. The root `Cargo.toml` has `publish = false`, and the crates depend
on each other through workspace paths. Treat Git tags and GitHub Releases as the release surface unless that changes.

## Version Rules

Use the root `Cargo.toml` workspace version as the release version for the Rust workspace, CLI, daemon, TUI, app runtime,
and bindings:

```toml
[workspace.package]
version = "0.1.0"
```

Use the same version number in:

- `v<version>` for the whole workspace;
- `marmotkit-v<version>` for generated app binding bundles;
- `crates/cli/CHANGELOG.md` for CLI-visible changes.

Use a new version when public behavior changes. That includes:

- UniFFI records, enums, object methods, async methods, or error variants;
- app runtime behavior that iOS or Android depends on;
- CLI, daemon, or TUI commands and JSON output;
- protocol, transport, storage, or vector changes that downstream users need to pin.

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

Use this for a versioned Darkmatter source/library release.

1. Update the workspace version in `Cargo.toml`.
2. Move relevant `crates/cli/CHANGELOG.md` entries out of `Unreleased`.
3. Update docs that describe changed public behavior.
4. Run the preflight checks above.
5. Create an annotated tag:

   ```sh
   git tag -a v0.1.0 -m "darkmatter v0.1.0"
   git push origin v0.1.0
   ```

6. Create or update the GitHub Release for `v0.1.0` on the Darkmatter repo releases page.
7. Include release notes that name the source commit, major user-visible changes, and any migration notes.

Until a dedicated whole-workspace release workflow exists, the whole-workspace GitHub Release is a source release. The
GitHub-generated source archives are the downloadable artifacts.

## MarmotKit Binding Release

Use this when app repos need pinned generated bindings instead of a local Darkmatter checkout.

The workflow lives at:

```text
.github/workflows/bindings.yaml
```

It runs only when a tag matching `marmotkit-v*` is pushed. The workflow validates version-like tags such as
`marmotkit-v0.1.0`, builds both binding bundles, and creates or updates the matching GitHub Release.

Create the tag:

```sh
git tag -a marmotkit-v0.1.0 -m "MarmotKit v0.1.0"
git push origin marmotkit-v0.1.0
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

After updating an app repo, run that app's normal compile and smoke checks. Binding generation passing in Darkmatter
does not prove the app has adapted to every public API change.

## CLI And Homebrew Release

The CLI package is `darkmatter-cli`; the installed binaries are:

- `dm`
- `dmd`

Before a CLI release, run:

```sh
cargo test -p darkmatter-cli
cargo test -p marmot-app
```

Then smoke-test installed binaries from the release commit:

```sh
install_root="$(mktemp -d)"
cargo install --path crates/cli --locked --bins --root "$install_root" --force
"$install_root/bin/dm" --help
"$install_root/bin/dmd" --help
DM_HOME="$(mktemp -d)" DM_SECRET_STORE=file "$install_root/bin/dm" account create
```

Homebrew release notes live in:

```text
docs/release/dm-homebrew.md
```

Use that checklist when updating `marmot-protocol/homebrew-tap`.

## Correcting A Release

If a tag points at the wrong commit and nobody should consume it, delete and recreate the tag before app repos pin it:

```sh
git tag -d marmotkit-v0.1.0
git push origin :refs/tags/marmotkit-v0.1.0
git tag -a marmotkit-v0.1.0 -m "MarmotKit v0.1.0"
git push origin marmotkit-v0.1.0
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
