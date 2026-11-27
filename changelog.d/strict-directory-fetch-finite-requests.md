### Changed

- Migrated strict directory reads (`fetch_directory_events_with_completion`) in `transport-nostr` onto chunked `FiniteRequests` using per-REQ raw-vs-admitted EVENT accounting (`raw_items == received_items`) and retired the duplicate `DirectoryWireTransport` wrapper.
