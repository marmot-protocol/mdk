//! Directory tests that need a real `MarmotApp`. They drive the directory
//! through the app's resources (its caches, relay plane, account home and
//! runtime), so they live with the app when the directory moves into
//! `nostr-directory` (PR 6 of `docs/marmot-architecture/review/brief-directory.md`).
//! The directory's own tests stay beside its code.

mod cached_search;
mod member_key_packages;
mod methods;
mod previews;
mod search;
mod sync;
