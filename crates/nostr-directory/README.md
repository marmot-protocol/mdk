# nostr-directory

The directory of other people's public Nostr data for a Marmot app: who an account is, which relays reach them,
which KeyPackages to invite them with, and who matches a search.

It owns the logic and the cache schema. The host app owns the resources: it opens and keys each account's encrypted
cache, resolves account labels, keeps block lists, and hands the directory open handles through three traits. In
MDK that host is [`marmot-app`](../marmot-app), which re-exports the directory's types at their old
`marmot_app::...` paths.

## What is here

- **Lookups and refreshes.** Relay lists, profiles, follow lists and KeyPackages for other accounts, fetched from
  their relays and kept in a per-account cache, merged with the shared public tier the app's `storage-sqlite`
  database keeps.
- **Direct-follow availability.** A selected account's cached kind:3 follows projected as `ready`, `unknown`, or a
  temporary `not_found`, with publication and freshness metadata but no KeyPackage bytes. Refresh is bounded and
  cancellable; paged reads use that account's encrypted cache plus shared per-slot replacement metadata.
- **Member KeyPackage resolution.** Resolving a whole roster before a group create or invite: canonical ids, relay
  discovery, and every valid, fresh KeyPackage of each account (one per device, at most 20), skipping those the
  account asked to delete, with bounded recovery when the first relays don't answer.
- **Search.** Streaming web-of-trust search with optional Open Ranking discovery, and network-free search over cached
  data. Cached search filters public fields in SQL, resolves the newest profiles across stores, and ranks matches
  before decoding at most the requested limit of profiles (10,000 maximum). Unicode lowercase matching treats
  punctuation literally. Streaming search uses the same local query before relay work.
- **Public event previews.** Verified previews of `nostr:` references in messages, stored in the directory cache.
- **The sync worker.** Keeps relay subscriptions current for known users and hands block-list events back to the app.
- **The cache schema.** The per-account SQLCipher cache's tables, frozen schemas and numbered migrations.

## How a host uses it

A host implements `DirectoryResources` (its accounts, the caches, shared storage), `BlockListSink` (block-list
adoption and reconciliation) and `DirectoryObserver` (usage analytics), then builds a `Directory` over them with a
`DirectoryConfig` and a shared `DirectoryState`. `marmot-app` does this in `src/directory_resources.rs` and hands the
service out as `MarmotApp::directory()`.

`resolve_compatible_member_key_packages` takes a `MemberResolutionPolicy`. `Partial` returns fresh packages for eligible
accounts with ordered per-account `member_outcomes`, including typed failures for unavailable accounts. An empty package
set is a report, not permission to create a group without its requested members. `Atomic` returns the first recipient
failure instead. Invalid references, storage failures and fetch-resource errors remain global errors under both
policies. Incomplete relay reads can fall back per account; an error from the completion fetch aborts the lookup.
Over-budget published member routes remain account-local and do not renew prewarm readiness.
`resolve_member_key_packages` and composition prewarm retain their atomic readiness contract.

`refresh_follow_availability` checks at most 100 direct follows, four at a time, with a 10-second target deadline and
a five-minute overall deadline. Each target uses at most two relay fetch calls: relay-list discovery when no safe
NIP-65 route is cached, then a KeyPackage/deletion read. A completed clean miss with no observed publications stays
`not_found` for 15 minutes. Incomplete, malformed, deleted or replaced reads stay `unknown`. Results commit per target,
repeated calls share an active refresh, and completed refreshes have a 60-second cadence. `follow_availability_page`
returns up to 100 rows in account-id keyset order and hides unfollows. Expired or replaced positives and any negative
with replacement or eviction evidence downgrade to `unknown`.

The crate's API is what its root re-exports, plus the `config` and `error` modules. The `test-support` feature adds
the hooks `marmot-app`'s directory tests use; production builds never enable it.
