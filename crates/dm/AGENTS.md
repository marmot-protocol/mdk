# AGENTS.md - dm

Real CLI app surface for the Darkmatter/Marmot stack.

## Scope

- Keep `dm` product-facing. Do not add smoke-test-only commands here.
- Keep command output useful for humans by default and stable JSON when `--json` is passed.
- Reuse the real account/session/transport stack through `marmot-account` and `marmot-app`.
- Do not depend on `marmot-lab` for product-facing account, group, message, or sync commands.
- Do not print or log nsecs, secret key hex, plaintext database keys, or other key material.
- Treat JSON response shapes as future TUI/API inputs; change them deliberately.

## Verification

Start with the focused crate tests:

```sh
cargo test -p darkmatter-cli
cargo test -p marmot-app
```

Then run the lab regression only if legacy lab wiring changed:

```sh
cargo test -p marmot-lab
```
