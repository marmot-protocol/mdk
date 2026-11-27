### Added

- Add NIP-46 remote-signing support to `wn` and `wnd`:
  - `wn login --bunker-stdin` / `wn accounts nip46 login --bunker-stdin` read `bunker://` URIs from stdin (rejecting NIP-46 URIs on argv), review and confirm permissions (interactively or via `--approve-permissions`), connect, and log in via `MarmotAppRuntime::nip46_login` with optional `--default-relays` and `--bootstrap-relays` (publishing missing relay lists to the default relays).
  - `wn login --nostrconnect` / `wn accounts nip46 login --nostrconnect` support client-initiated `nostrconnect://` pairing (printing the pairing offer URI before awaiting `connect` and login, both locally and streamed through `wnd`).
  - `wn accounts nip46 register`, `status`, and `remove` manage existing NIP-46 external-signing sessions.
  - `wn accounts list`, `wn accounts status`, and `wn whoami` report `external_signing` and `signing_mode` (`local`, `external`, or `public`).
  - `wnd` startup restores persisted NIP-46 accounts independently via `MarmotAppRuntime::start()` without blocking local accounts, and one-shot `wn` commands resume sessions on demand via `nip46_resume`.
  - All signing-capable `wn` and `wnd` operations (`messages`, `groups`, `chats`, `keys`, `profile`, `relays`, `sync`, `follows`, `media`, `devices`, and streaming subscriptions) now accept `external_signing` accounts while keeping `export-nsec` disabled.
