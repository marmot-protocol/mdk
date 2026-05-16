# AGENTS.md - dm

Real CLI app surface for the Darkmatter/Marmot stack.

## Scope

- Keep `dm` product-facing. Do not add smoke-test-only commands here.
- Keep command output useful for humans by default and stable JSON when `--json` is passed.
- Reuse the real account/session/transport stack through `marmot-account` and `marmot-app`.
- Do not depend on `marmot-lab` for product-facing account, group, message, or sync commands.
- Keep Nostr public keys as the CLI identity layer. Do not introduce user-label account selection in product commands.
- Do not add a CLI address-book/user-directory browsing namespace unless the product direction changes. Pubkeys are passed
  directly to group/invite/key commands; directory warming and search live under `marmot-app`/daemon behavior.
- Keep one spelling per product capability: `keys`, `chats`, top-level `--account <npub-or-hex>`, and positional basics
  for common group and message flows. Do not add hidden compatibility aliases for old command shapes.
- Keep `dm tui` as a thin Ratatui shell over the real `dm --json` command surface. It may add approachable navigation
  and slash commands, but it should not become a second app runtime or bypass `marmot-app`/daemon behavior.
- Keep TUI account onboarding on top of `dm account create`; redact `nsec` import input before rendering it in the
  composer.
- Keep TUI daemon controls on top of `dm daemon start|stop|status`; live refresh should observe daemon state and avoid
  interrupting active composer input.
- Keep daemon behavior real. `dm daemon start|stop|status`, the `dmd` binary, socket-backed execution, pid/log files, and
  background sync should be covered when touched. Background sync should also refresh the app-level Nostr user directory
  for local signing accounts.
- Do not print or log nsecs, secret key hex, plaintext database keys, or other key material.
- Treat JSON response shapes as TUI/API inputs; change them deliberately.

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
