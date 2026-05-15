# marmot-app

`marmot-app` is the first non-lab app runtime bridge.

It wires the app-owned `AccountHome` to encrypted session storage, the Nostr MLS peeler, the Nostr transport adapter, and
a local file relay for deterministic CLI/TUI development. The crate is intentionally below presentation layers like `dm`
and above the generic account/session/engine crates.

It owns the first app projections:

- shared app cache in `app-cache.sqlite3` for discovered user relay lists and KeyPackages;
- per-account SQLCipher app state in `accounts/<label>/app.sqlite3` for joined groups, app-component profile/image
  projections, seen relay events, and sent/received message projections.

The app runtime exposes those projections through account status, group listing/showing, and message listing APIs so CLI
and TUI surfaces can inspect app state without opening the databases directly.

New-account bootstrap can publish the required NIP-65, inbox kind `10050`, and KeyPackage kind `10051` relay-list events
from a default relay set, while import flows can check whether those lists are already present before writing local
account state. The same status API can fetch those relay-list events from supplied bootstrap relays and store discovered
user relay/KeyPackage data for deterministic CLI/TUI development.

The local file relay models relay boundaries by endpoint. Fetching account relay lists or KeyPackages from specific
`marmot-local://...` bootstrap/source relays only sees records published to those endpoints, which keeps CLI and future
TUI discovery behavior honest during local tests.
