# HPKE 0.7 fixed-KEM compatibility backport

The pinned OpenMLS provider requires HPKE 0.7. Published `hpke-rs 0.7.0`
requires `hpke-rs-libcrux =0.7.0`, which requires vulnerable
`libcrux-kem =0.0.9`. A lockfile-only update cannot select fixed KEM 0.0.10.
HPKE 0.8 changes provider/KDF/randomness interfaces and is outside this repair.

This directory preserves the published hpke-rs-libcrux 0.7.0 Rust source.
The only upstream source modification is the normalized Cargo.toml dependency:
`libcrux-kem =0.0.9` becomes `=0.0.10`. The package version is unchanged.
`Cargo.toml.orig` records the original upstream manifest; Cargo does not use it.
The registry receipt and nested upstream Cargo.lock are omitted; MDK's root
Cargo.lock owns the adopted resolution. Licensing and provenance are in NOTICE,
LICENSE-MPL-2.0, and .cargo_vcs_info.json. BACKPORT.md and security-regression/
are local additions, not upstream files. Build output is excluded by .gitignore.

Fixed advisories:

- [RUSTSEC-2026-0330](https://rustsec.org/advisories/RUSTSEC-2026-0330): reject short hybrid encapsulation seeds.
- [RUSTSEC-2026-0331](https://rustsec.org/advisories/RUSTSEC-2026-0331): reject short hybrid keys without panicking.

This repair adds no advisory suppressions. The fixed KEM brings its matching libcrux
transitive dependency versions; older versions needed by the unchanged HPKE
provider coexist. OpenMLS and HPKE's public 0.7 interfaces stay pinned.

Container builders copy `vendor/` alongside the workspace manifests. CI treats
vendored files as build inputs, including `Readme.md`, which the provider embeds
with `include_str!`.

## Reproduce the compatibility and security checks

From the MDK repository root:

```sh
CARGO_BUILD_JOBS=2 cargo test --locked --manifest-path vendor/hpke-rs-libcrux/security-regression/Cargo.toml --features mlkem
cargo --locked audit --file Cargo.lock
```

The isolated harness is excluded from MDK's workspace and has its own lockfile.
It enables HPKE's OpenMLS-required hazmat, serialization and experimental features,
compiles the libcrux provider with std and optional ML-KEM support, verifies
bidirectional encryption with the unchanged RustCrypto 0.7 provider for X25519,
P256, XWing, ML-KEM-768 and ML-KEM-1024, and checks both advisory input classes.
It does not establish every platform's artifact compatibility; normal MDK CI
and release qualification still apply.

## Removal condition

Remove this directory, its workspace exclusion, and the root patch when a
published HPKE 0.7-compatible provider selects libcrux-kem >=0.0.10, or when a
separately reviewed OpenMLS/HPKE upgrade supplies that fix. Refresh the lockfile,
rerun these interoperability/security regressions, and verify cargo audit before
removing the compatibility patch.
