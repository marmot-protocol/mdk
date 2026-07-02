# dm Homebrew Release Checklist

This checklist covers the project-side release steps for the namespaced Homebrew tap.

Intended install path:

```sh
brew install marmot-protocol/tap/darkmatter
```

The tap lives at:

```text
github.com/marmot-protocol/homebrew-tap
```

The canonical formula lives in the tap repo:

```text
github.com/marmot-protocol/homebrew-tap/Formula/darkmatter.rb
```

It should install both binaries:

- `dm`
- `dmd`

## Tap Repo Setup

1. Keep the formula in `github.com/marmot-protocol/homebrew-tap/Formula/darkmatter.rb`.
2. Keep the formula name `darkmatter`; the installed binaries remain `dm` and `dmd`.
3. Do not keep a second live formula in this repo.
4. Do not submit this formula to `homebrew/core` while Darkmatter is still candidate work.

Minimum tap layout:

```text
README.md
Formula/
  darkmatter.rb
```

Recommended tap layout:

```text
README.md
Formula/
  darkmatter.rb
.github/
  workflows/
    tests.yml
    publish.yml
```

A `Brewfile` is optional. Homebrew does not need one to use the tap. Add one only if the tap repo wants a maintainer
bootstrap command such as `brew bundle` for local tooling. Do not use a `Brewfile` as the package definition; the
formula is the package definition.

The tap can hold more packages later:

```text
Formula/
  darkmatter.rb
  another-tool.rb
Casks/
  some-app.rb
cmd/
  brew-some-command
```

Use `Formula/` for CLI/source-built packages, `Casks/` for app bundles, and `cmd/` only for custom `brew` subcommands.

## Before Tagging

1. Confirm the CLI version in the workspace root `Cargo.toml`. The first release is `0.1.0`, tagged as `v0.1.0`.
2. Confirm `Cargo.lock` is committed and current.
3. Run the focused CLI checks:

   ```sh
   cargo test -p darkmatter-cli
   cargo test -p marmot-app
   ```

4. Run the wider workspace checks:

   ```sh
   just fmt-check
   just check
   just clippy
   just test
   just tamarin
   ```

5. Run the installed-binary smoke test from a clean checkout:

   ```sh
   install_root="$(mktemp -d)"
   cargo install --path crates/cli --locked --bins --root "$install_root" --force
   "$install_root/bin/dm" --help
   "$install_root/bin/dmd" --help
   DM_HOME="$(mktemp -d)" DM_SECRET_STORE=file "$install_root/bin/dm" account create
   ```

6. Update user-facing docs if commands, defaults, or daemon behavior changed:

   - `crates/cli/CHANGELOG.md`
   - `crates/cli/README.md`
   - `crates/cli/AGENTS.md`
   - this checklist

## Tag And Formula Source

1. Create an annotated tag from the commit whose `Cargo.toml` version matches the tag:

   ```sh
   git tag -a v0.1.0 -m "darkmatter v0.1.0"
   git push origin v0.1.0
   ```

2. For the current private source repo, update `Formula/darkmatter.rb` in `marmot-protocol/homebrew-tap` to use the
   private Git tag plus the exact commit revision:

   ```ruby
   url "ssh://git@github.com/marmot-protocol/darkmatter.git",
       tag:      "v0.1.0",
       revision: "<tagged-commit-sha>"
   ```

   Users and CI runners need GitHub access to `marmot-protocol/darkmatter` for this source build path.

3. If the source repo is public, prefer the GitHub source archive plus `sha256`:

   ```sh
   curl -L -o darkmatter-v0.1.0.tar.gz \
     https://github.com/marmot-protocol/darkmatter/archive/refs/tags/v0.1.0.tar.gz
   shasum -a 256 darkmatter-v0.1.0.tar.gz
   ```

   Then set:

   - `url "https://github.com/marmot-protocol/darkmatter/archive/refs/tags/v0.1.0.tar.gz"`
   - `sha256 "<archive-sha256>"`
   - Omit `revision 0` for the first formula update.

## Test The Tap Formula

Run these from a checkout of `github.com/marmot-protocol/homebrew-tap`:

```sh
brew update
brew audit --strict --online Formula/darkmatter.rb
brew install --build-from-source Formula/darkmatter.rb
brew test Formula/darkmatter.rb
brew uninstall darkmatter
```

Then test the namespaced install path:

```sh
brew tap marmot-protocol/tap
brew install marmot-protocol/tap/darkmatter
dm --help
dmd --help
brew test marmot-protocol/tap/darkmatter
```

## Bottle Path

Source builds are enough for the first tap release. Add bottles after release CI exists.

While `marmot-protocol/darkmatter` is private, bottle CI needs either access to the source repo or a prebuilt source
archive/release asset it can download. Public source archives avoid that extra CI setup.

Manual bottle flow:

```sh
brew install --build-bottle marmot-protocol/tap/darkmatter
brew bottle marmot-protocol/tap/darkmatter
```

Commit the generated `bottle do` block to `marmot-protocol/homebrew-tap` after the bottle artifacts are uploaded to the
tap's release storage.

## Post-Release Smoke

Run this on a machine without a local source checkout on `PATH`:

```sh
brew install marmot-protocol/tap/darkmatter
which dm
which dmd
dm --help
dmd --help
DM_HOME="$(mktemp -d)" DM_SECRET_STORE=file dm account create
brew uninstall darkmatter
```

## Current Limits

- The formula builds from source until bottles are published.
- While `marmot-protocol/darkmatter` is private, the formula should use the Git tag and exact revision. Public tarball
  URLs return 404 without authentication.
- The formula uses `cargo install --locked --bins --path crates/cli`, so source archives must include the workspace
  `Cargo.lock`.
- crates.io install is a separate release track. The workspace currently has `publish = false`, and the CLI depends on
  local workspace crates.
