# AGENTS.md - crates/marmot-account

Agent-facing map for the Marmot account identity crate.

## Scope

Owns account identity, files and secrets: account home layout, local account records, setup journals, signing-key
storage and NIP-49 export. For the human overview see [`README.md`](README.md).

It must not own MLS state, sessions, transport, publish work, or anything else that needs a protocol crate; the
account-device runtime is `marmot-session`'s. It must not own UI projection, notifications, or relay-list discovery.

## Layout

`src/lib.rs` is a thin facade: crate docs, `mod` declarations, and `pub use` re-exports. Every public item keeps its
`marmot_account::Item` path. Source is split into focused modules:

- `error.rs` — the `AccountHomeError` enum and the `AccountHomeResult` alias.
- `home.rs` — `AccountHome` and `AccountSummary`; owns the account-record layout and signing-key lifecycle.
- `nip49_export.rs` — NIP-49 `ncryptsec` export policy (fixed scrypt cost, non-empty passphrase, key-security byte);
  crypto is delegated to the upstream `nostr` crate. Do not hand-roll NIP-49 here.
- `secret_store.rs` — `AccountSecretStore` trait with `LocalFileSecretStore` and `KeychainSecretStore`.
- `keyring.rs` — platform keyring entry construction, iOS service versioning and secret writes, store init (per-OS
  `#[cfg]` cascade), and keyring-error mapping.
- `io.rs` — JSON read/write helpers, atomic private- and secret-file writes, and account-label validation.

Tests: `tests/home.rs` (account home).

## Rules

- Depend on no protocol crate: no `cgka-*` crate, no `marmot-forensics`, no storage crate (mdk#2602). The bindings,
  the CLI and the agent connector use this crate for identity alone.
- Keep CLI account-selection ergonomics and relay-list repair out of this crate; those belong in `wn` and `marmot-app`.
- Replace account-home files only through the `io.rs` writers, and never change a published file in place while a reader
  can still open it. Owner-only files that hold no key material (setup journal and context, onboarding checkpoints) use
  `write_private_json`/`write_private_bytes`. Only `write_secret_json` zeroes the inode it replaces, so read those files
  with `read_secret_json`, which rejects a read of an unlinked inode. Readiness polls read the setup journal while
  background setup rewrites it.
- Do not log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key material.

## Verification

```sh
cargo test -p marmot-account
```
