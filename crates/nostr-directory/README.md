# nostr-directory

The directory of other people's public Nostr data for a Marmot app: who an account is, which relays reach them,
which KeyPackage to invite them with, and who matches a search.

It owns the logic and the cache schema. The host app owns the resources: it opens and keys each account's encrypted
cache, resolves account labels, keeps block lists, and hands the directory open handles through three traits. In
MDK that host is [`marmot-app`](../marmot-app), which re-exports the directory's types at their old
`marmot_app::...` paths.

## What is here

- **Lookups and refreshes.** Relay lists, profiles, follow lists and KeyPackages for other accounts, fetched from
  their relays and kept in a per-account cache, merged with the shared public tier the app's `storage-sqlite`
  database keeps.
- **Member KeyPackage resolution.** Resolving a whole roster before a group create or invite: canonical ids, relay
  discovery, fresh KeyPackages, and bounded recovery when the first relays don't answer.
- **Search.** Streaming web-of-trust search with optional Open Ranking discovery, and network-free search over cached
  data.
- **Public event previews.** Verified previews of `nostr:` references in messages, stored in the directory cache.
- **The sync worker.** Keeps relay subscriptions current for known users and hands block-list events back to the app.
- **The cache schema.** The per-account SQLCipher cache's tables, frozen schemas and numbered migrations.

## How a host uses it

A host implements `DirectoryResources` (its accounts, the caches, shared storage), `BlockListSink` (block-list
adoption and reconciliation) and `DirectoryObserver` (usage analytics), then builds a `Directory` over them with a
`DirectoryConfig` and a shared `DirectoryState`. `marmot-app` does this in `src/directory_resources.rs` and hands the
service out as `MarmotApp::directory()`.

The crate's API is what its root re-exports, plus the `config` and `error` modules. The `test-support` feature adds
the hooks `marmot-app`'s directory tests use; production builds never enable it.

See the [directory brief](../../docs/marmot-architecture/review/brief-directory.md) for why the boundary sits where it
does.
