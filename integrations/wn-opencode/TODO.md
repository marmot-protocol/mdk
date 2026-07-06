# Pre-PR checklist

This branch contains a working prototype of `wn-opencode`: a Rust adapter that
bridges Marmot groups to opencode sessions via `wn-agent`'s control socket.
It runs end-to-end today, but before opening a PR against `marmot-protocol/mdk`
the following work needs to happen. Everything below is scoped to bringing the
code up to MDK's contributor standards documented in `AGENTS.md` and
`docs/marmot-architecture/observability-privacy.md`.

## Privacy compliance (MUST)

- [ ] **Remove `short(hex)` from every tracing call.** Group ids, sender
      account ids, message ids, and session ids may not appear in logs — even
      truncated. Replace with counts, method names, and privacy-safe error
      kinds. All ~13 call sites in `src/main.rs`.
- [ ] **Purge raw error interpolation.** Every `"{e}"`, `format!("... {e}")`,
      and `error = %err` reaches the log verbatim and can carry paths, URLs,
      or attacker-controlled content. Introduce a `privacy_safe_kind()`
      classifier that maps errors to short stable strings and log
      `error_kind = kind`. All ~13 call sites.
- [ ] **Add explicit `target:` and `method:` fields** to every `info!` /
      `warn!` / `debug!` / `error!` call.
- [ ] **Run the tracing audit locally** and confirm it passes:
      `cargo test -p cgka-conformance-simulator tracing_audit`.

## Storage hardening (MUST)

- [ ] **Use `fs-private` for the state file and directory.** The current code
      calls `tokio::fs::create_dir_all` + plain `tokio::fs::write` for
      `sessions.json`. MDK's contract is that any local socket or state file
      is restrictive-by-construction (0700 dir, 0600 file). Depend on
      `fs-private` from the workspace and use it for creation.

## Workspace integration

- [x] Cargo.toml switched to workspace-relative `agent-control` path.
- [ ] Add `integrations/wn-opencode` to root `Cargo.toml [workspace].members`.
- [ ] Switch to workspace-inherited dependency versions
      (`tokio.workspace = true`, `serde.workspace = true`, etc.) matching the
      pattern in `crates/agent-connector/Cargo.toml`.
- [ ] Verify `cargo build --workspace` succeeds from the repo root.

## Docs

- [ ] Rewrite `README.md` to match the tone and shape of
      `integrations/hermes/marmot/README.md`: what it is, one-line install,
      config env vars, verification steps, security notes.
- [ ] Add `AGENTS.md` describing the scope and rules (control-plane only, no
      MLS/crypto/QUIC logic here, privacy-safe logging only).
- [ ] Symlink `CLAUDE.md -> AGENTS.md` (required per repo convention).
- [ ] Reference from top-level `README.md` under the integrations section.

## Code quality

- [ ] `cargo fmt --check` clean.
- [ ] `cargo clippy --workspace -- -D warnings` clean.
- [ ] `cargo test -p wn-opencode` — currently 11 tests, keep them and add
      more where reasonable (protocol client tests using `tokio::io::duplex`,
      opencode subprocess tests using a mock binary).
- [ ] Consider splitting `main.rs` (currently ~1040 lines) into modules
      before PR: `config`, `store`, `repo`, `client`, `opencode`, `bridge`.

## Follow-up features (not blocking PR, note in README)

- [ ] Group rename to opencode session title. Requires two upstream changes
      that don't exist yet:
      1. A `RenameGroup` request variant on `AgentControlRequest` (currently
         only observable via `GroupStateChanged` events).
      2. A way to read opencode session titles programmatically (the
         `--format json` stream does not include them; would need
         `opencode serve` HTTP API or a `--format json` flag on
         `opencode session list`).

## What already works

- 1039-line single-file adapter under `src/main.rs`.
- 11 unit tests: repo picker grammar, chunker (unicode safe), session store
  persistence (fresh + legacy bare-string format).
- Per-group serialized opencode invocation (one in-flight per group).
- Hard timeout (default 300s), stderr capture with ANSI stripping.
- Idempotency keys on `SendFinal` composed of inbound message id + chunk
  index to survive adapter crashes without duplicating output.
- Session store at `$XDG_STATE_HOME/wn-opencode/sessions.json`,
  atomic rename on write.
- Admin allowlist enforced twice: `wn-agent`'s welcomer allowlist for who
  can invite the agent, plus the adapter's own filter for whose messages
  it will process.
