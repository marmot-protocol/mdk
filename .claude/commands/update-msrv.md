Please update the Minimum Supported Rust Version (MSRV): $ARGUMENTS.

Follow these steps:

1. Determine the new MSRV version from arguments (e.g., "1.91.0")
2. Update MSRV in all required locations:
   - `/Cargo.toml` - `workspace.package.rust-version`
   - `/scripts/check-msrv.sh` - `msrv` variable
   - `/.github/workflows/ci.yml` - matrix `rust` array
   - `docs/DEVELOPMENT.md` - hard-coded MSRV version references
   - `README.md` - MSRV references (if any)
3. Verify the new MSRV works:
   - Install the new Rust version: `rustup install {version}`
   - Run checks: `./scripts/check-all.sh {version}`
4. Check if any dependencies require a newer Rust version
5. Update any code that can now use newer Rust features (optional)
6. Run `just precommit` to ensure all checks pass
7. Add changelog entry (breaking change if MSRV increases significantly)
8. Create a descriptive commit message
9. Push and create a PR

MSRV update checklist:
- ✅ All version references updated
- ✅ CI configuration updated
- ✅ Scripts updated
- ✅ Documentation updated
- ✅ Tests pass with new MSRV
- ✅ Dependencies compatible with new MSRV
