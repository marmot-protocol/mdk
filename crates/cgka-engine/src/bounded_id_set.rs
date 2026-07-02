//! [`BoundedIdSet`] is a capacity-bounded FIFO membership cache.
//!
//! The engine keeps two in-memory dedup caches — `seen_message_ids` and
//! `sent_message_ids` — that back `StaleReason::AlreadySeen` / `OwnEcho`. The
//! durable `MessageRecord` store is authoritative (checked first via
//! `recorded_message_outcome` in `do_ingest`), so these caches are a hot-process
//! fast path, not history. Backing them with a plain `HashSet` made them
//! append-only: RSS climbed monotonically with total lifetime message volume on
//! always-on clients (agents, daemons, the `dm-agent` connector).
//!
//! This type bounds that growth: it tracks membership in a `HashSet` for O(1)
//! `contains`, and insertion order in a `VecDeque` so the oldest id is evicted
//! once the cap is reached. A re-inserted id is a no-op (it does not refresh
//! recency or consume another slot), so duplicate traffic cannot inflate the
//! cap accounting. Eviction only affects the in-memory fallback; durable storage
//! still classifies ids that age out of the cache. For outbound OpenMLS bytes,
//! the engine persists both the transport id and a content-derived `Sent`
//! marker so re-wrapped own echoes remain `OwnEcho` after cache eviction or
//! restart.

use std::collections::{HashSet, VecDeque};
use std::hash::Hash;

/// Capacity bound for the engine's in-memory dedup caches.
///
/// Sized as a hot-process fallback in front of the authoritative durable
/// `MessageRecord` store, not as full message history. 100k 32-byte ids plus
/// the FIFO/Set bookkeeping is on the order of a few MiB per cache — large
/// enough that practically all live duplicate/echo traffic stays in-cache, but
/// bounded so RSS can no longer climb with total lifetime message volume. IDs
/// that age out of the cache are still classified by durable storage; outbound
/// OpenMLS sends persist a content-derived `Sent` marker for re-wrapped own
/// echoes whose transport id changed.
pub(crate) const DEDUP_CACHE_CAPACITY: usize = 100_000;

/// A capacity-bounded FIFO membership set. Insertion-ordered eviction: once
/// `capacity` distinct entries are held, inserting a new entry evicts the
/// oldest. Re-inserting an existing entry is a no-op.
#[derive(Debug, Clone)]
pub(crate) struct BoundedIdSet<T: Clone + Eq + Hash> {
    members: HashSet<T>,
    order: VecDeque<T>,
    capacity: usize,
    /// Monotonic counter bumped on every membership change (insert or the
    /// eviction that an insert triggers). Lets callers cache a derived view of
    /// the set (e.g. the convergence hex-encoded snapshot, #636) and rebuild it
    /// only when the set actually changed, instead of once per convergence pass.
    generation: u64,
}

impl<T: Clone + Eq + Hash> BoundedIdSet<T> {
    /// Creates an empty set bounded to `capacity` entries.
    ///
    /// `capacity` must be non-zero; a zero-capacity cache could never hold the
    /// id it just inserted, which would silently defeat dedup.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "BoundedIdSet capacity must be non-zero");
        Self {
            members: HashSet::new(),
            order: VecDeque::new(),
            capacity,
            generation: 0,
        }
    }

    /// Returns `true` if `value` is currently cached.
    pub(crate) fn contains(&self, value: &T) -> bool {
        self.members.contains(value)
    }

    /// Inserts `value`, evicting the oldest entry if the cache is at capacity.
    ///
    /// Re-inserting an already-present value is a no-op: it neither refreshes
    /// recency nor consumes another slot, so duplicate traffic cannot inflate
    /// the cap accounting.
    pub(crate) fn insert(&mut self, value: T) {
        if !self.members.insert(value.clone()) {
            return;
        }
        // Membership changed (new id, plus any eviction below) — bump once so a
        // no-op re-insert above leaves the generation (and any derived cache)
        // untouched.
        self.generation = self.generation.wrapping_add(1);
        self.order.push_back(value);
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.members.remove(&evicted);
            }
        }
    }

    /// A token that changes whenever the set's membership changes. A derived
    /// snapshot is still current iff the generation matches the one captured
    /// when it was built.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Iterates the cached entries in no particular order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.members.iter()
    }

    /// Number of cached entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.members.len()
    }

    /// Configured capacity bound.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_and_never_exceeds_capacity() {
        let mut set = BoundedIdSet::with_capacity(3);
        for id in 0..10u32 {
            set.insert(id);
            assert!(set.len() <= set.capacity());
        }
        // Only the last `capacity` ids remain; older ones were evicted FIFO.
        assert_eq!(set.len(), 3);
        assert!(set.contains(&9));
        assert!(set.contains(&8));
        assert!(set.contains(&7));
        assert!(!set.contains(&6));
        assert!(!set.contains(&0));
    }

    #[test]
    fn duplicate_inserts_do_not_inflate_cap_accounting() {
        let mut set = BoundedIdSet::with_capacity(3);
        set.insert(1u32);
        set.insert(2);
        // Re-inserting an existing id must not consume a slot or evict another.
        for _ in 0..100 {
            set.insert(1);
        }
        assert_eq!(set.len(), 2);
        set.insert(3);
        assert_eq!(set.len(), 3);
        // The duplicate re-inserts did not refresh recency: id 1 is still the
        // oldest, so the next distinct insert evicts it, not id 2 or 3.
        set.insert(4);
        assert_eq!(set.len(), 3);
        assert!(!set.contains(&1));
        assert!(set.contains(&2));
        assert!(set.contains(&3));
        assert!(set.contains(&4));
    }

    #[test]
    fn iter_yields_all_current_members() {
        let mut set = BoundedIdSet::with_capacity(4);
        set.insert(10u32);
        set.insert(20);
        set.insert(20);
        set.insert(30);
        let collected: HashSet<u32> = set.iter().copied().collect();
        assert_eq!(collected, HashSet::from([10, 20, 30]));
    }

    // Compile-time guard: a zero cap would silently defeat dedup.
    const _: () = assert!(DEDUP_CACHE_CAPACITY > 0);

    #[test]
    fn default_dedup_cap_is_wired_and_bounds_growth() {
        // The engine constructs both dedup caches with `DEDUP_CACHE_CAPACITY`
        // (see `engine.rs`). Prove a cache built with it reports that capacity
        // and never grows past it even under heavy insertion.
        let mut set = BoundedIdSet::with_capacity(DEDUP_CACHE_CAPACITY);
        assert_eq!(set.capacity(), DEDUP_CACHE_CAPACITY);
        for id in 0..(DEDUP_CACHE_CAPACITY as u64 + 1_000) {
            set.insert(id);
        }
        assert_eq!(set.len(), DEDUP_CACHE_CAPACITY);
    }

    #[test]
    #[should_panic(expected = "BoundedIdSet capacity must be non-zero")]
    fn zero_capacity_panics() {
        let _ = BoundedIdSet::<u32>::with_capacity(0);
    }

    #[test]
    fn generation_bumps_only_on_membership_change() {
        // Backs the #636 convergence hex-snapshot cache: the generation must
        // change on any real insert (and its eviction) but NOT on a no-op
        // re-insert, or the cache would either serve stale data or rebuild
        // needlessly.
        let mut set = BoundedIdSet::with_capacity(2);
        assert_eq!(set.generation(), 0);
        set.insert(1u32);
        let after_first = set.generation();
        assert_ne!(after_first, 0);
        // No-op re-insert: membership unchanged, generation stable.
        set.insert(1);
        assert_eq!(set.generation(), after_first);
        // New id: generation advances.
        set.insert(2);
        let after_second = set.generation();
        assert_ne!(after_second, after_first);
        // Insert past capacity evicts the oldest: still a membership change.
        set.insert(3);
        assert_ne!(set.generation(), after_second);
    }
}
