### Fixed

- Existing-key setup offers signer reconnection when an external signer cannot authorize an inbox check. If a signed inbox check fails at a relay, Retry can try another relay already listed in the account's inbox declaration.
