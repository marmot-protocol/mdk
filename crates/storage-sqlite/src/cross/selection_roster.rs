//! Private projected-roster baseline. This does not certify live readiness or
//! admit Participants; the caller must own the account and read transaction.
use crate::base::connection::CachedSql;
use crate::{SqliteResultExt, deserialize};
use cgka_traits::Group;
use cgka_traits::storage::StorageError;
use rusqlite::{Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};

/// Conservative bound derived from the existing64-node,64-values-per-node codec.
pub const MAX_SELECTED_MEMBER_KEYS: usize = 64 * 64;

pub struct SelectedMemberKeys {
    key_count: usize,
    by_key: HashMap<Vec<u8>, usize>,
}
impl SelectedMemberKeys {
    pub fn new(keys: &[[u8; 32]]) -> Result<Self, RosterReadError> {
        if keys.is_empty() || keys.len() > MAX_SELECTED_MEMBER_KEYS {
            return Err(RosterReadError::InvalidKeys);
        }
        Self::for_catalog(keys)
    }
    /// Whole request catalogs may combine multiple independently valid smart
    /// rules. Caller charges this union to its capture budget; there is no new
    /// global one-rule cardinality limit.
    pub fn for_catalog(keys: &[[u8; 32]]) -> Result<Self, RosterReadError> {
        Self::from_slices(keys.iter().map(|key| key.as_slice()))
    }
    /// Legacy member criteria are not smart-codec public keys. The compiler
    /// may select arbitrary decoded identity lengths; impossible nonhex text
    /// matches remain host presentation comparisons, not guessed byte keys.
    pub fn for_legacy_catalog(keys: &[Vec<u8>]) -> Result<Self, RosterReadError> {
        Self::from_slices(keys.iter().map(Vec::as_slice))
    }
    fn from_slices<'a>(
        keys: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<Self, RosterReadError> {
        let key_count = keys.len();
        let mut by_key = HashMap::new();
        by_key
            .try_reserve(keys.len())
            .map_err(|_| RosterReadError::ResourceExhausted)?;
        for (index, key) in keys.enumerate() {
            if key.is_empty() {
                return Err(RosterReadError::InvalidKeys);
            }
            let mut identity = Vec::new();
            identity
                .try_reserve_exact(key.len())
                .map_err(|_| RosterReadError::ResourceExhausted)?;
            identity.extend_from_slice(key);
            if by_key.insert(identity, index).is_some() {
                return Err(RosterReadError::InvalidKeys);
            }
        }
        Ok(Self { key_count, by_key })
    }
    pub fn len(&self) -> usize {
        self.key_count
    }
    pub fn is_empty(&self) -> bool {
        self.key_count == 0
    }
    pub fn index_of(&self, key: &[u8; 32]) -> Option<usize> {
        self.by_key.get(key.as_slice()).copied()
    }
    #[cfg(test)]
    pub(crate) fn single_condition(keys: &[[u8; 32]]) -> Result<Self, RosterReadError> {
        if keys.len() > 64 {
            return Err(RosterReadError::InvalidKeys);
        }
        Self::new(keys)
    }
    fn selected_index(&self, bytes: &[u8]) -> Option<usize> {
        self.by_key.get(bytes).copied()
    }
}
impl std::fmt::Debug for SelectedMemberKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMemberKeys")
            .field("count", &self.key_count)
            .finish()
    }
}

/// Frozen identity-only input corresponding to AppClient's actual profile-map
/// key presence. No names/directory lookup occurs while the connection is held.
#[derive(Clone, Copy)]
pub struct PeerInputs<'a> {
    pub active: Option<[u8; 32]>,
    pub local_profile_ids: &'a HashSet<[u8; 32]>,
}

/// Presence is separate from whether the chosen peer is one of the selected keys.
/// No arbitrary-length stored identity is copied into the returned evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectedPeer {
    pub selected_key: Option<usize>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectedRosterEvidence {
    pub(crate) selected_hits: Vec<u64>,
    pub(crate) roster_nonempty: bool,
    pub(crate) peer: Option<SelectedPeer>,
    pub presentation: Option<SelectedRosterPresentation>,
    pub active_account_is_member: Option<bool>,
    pub unrecoverable: bool,
}
/// Compact presentation-only roster facts, not a roster export.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectedRosterPresentation {
    pub peer_id_hex: Option<String>,
    pub member_count: i32,
    pub active_account_is_sole_member: bool,
    pub active_account_is_member: bool,
}
impl std::fmt::Debug for SelectedRosterPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedRosterPresentation")
            .field("member_count", &self.member_count)
            .finish_non_exhaustive()
    }
}
impl ProjectedRosterEvidence {
    pub fn contains(&self, index: usize) -> bool {
        self.selected_hits
            .get(index / 64)
            .is_some_and(|word| word & (1u64 << (index % 64)) != 0)
    }
    pub fn roster_nonempty(&self) -> bool {
        self.roster_nonempty
    }
    pub fn peer_present(&self) -> bool {
        self.peer.is_some()
    }
    pub fn hit_word_count(&self) -> usize {
        self.selected_hits.len()
    }
}
impl std::fmt::Debug for ProjectedRosterEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectedRosterEvidence")
            .field(
                "selected_hit_count",
                &self
                    .selected_hits
                    .iter()
                    .map(|word| word.count_ones())
                    .sum::<u32>(),
            )
            .field("roster_nonempty", &self.roster_nonempty)
            .field("peer_present", &self.peer.is_some())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RosterReadError {
    #[error("selected roster keys must be distinct and within the caller contract")]
    InvalidKeys,
    #[error("selected roster capture exceeds available transient resources")]
    ResourceExhausted,
    #[error("projected roster capture was cancelled")]
    Cancelled,
    #[error(transparent)]
    Storage(#[from] StorageError),
}
fn check_cancelled(cancelled: &impl Fn() -> bool) -> Result<(), RosterReadError> {
    if cancelled() {
        Err(RosterReadError::Cancelled)
    } else {
        Ok(())
    }
}

/// Exactly the typed GroupStorage::get_group acceptance path, using the caller's
/// held connection instead of reentering its mutex. Whole one-record/Group
/// allocation is intentional in this baseline; only returned evidence is bounded.
/// Fetch/serde are not preemptible. No runtime/FFI caller is provided here.
#[cfg(test)]
pub(crate) fn projected_roster_selected_keys_tx(
    conn: &Connection,
    lookup_group_id: &[u8],
    keys: &SelectedMemberKeys,
    peer_inputs: PeerInputs<'_>,
    cancelled: &impl Fn() -> bool,
) -> Result<ProjectedRosterEvidence, RosterReadError> {
    projected_roster_selection_context_tx(conn, lookup_group_id, keys, peer_inputs, None, cancelled)
}
pub(crate) fn projected_roster_selection_context_tx(
    conn: &Connection,
    lookup_group_id: &[u8],
    keys: &SelectedMemberKeys,
    peer_inputs: PeerInputs<'_>,
    presentation_limit: Option<usize>,
    cancelled: &impl Fn() -> bool,
) -> Result<ProjectedRosterEvidence, RosterReadError> {
    check_cancelled(cancelled)?;
    let record: Vec<u8> = conn
        .query_row_cached(
            "SELECT record FROM cgka_groups WHERE id = ?1",
            [lookup_group_id],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    check_cancelled(cancelled)?;
    // Do not compare decoded ID/epoch with SQL lookup columns: get_group does not.
    let group: Group = deserialize(&record)?;
    check_cancelled(cancelled)?;
    let mut selected_hits = vec![0u64; keys.len().div_ceil(64)];
    let mut first = None;
    let mut first_nonlocal = None;
    let mut first_nonself = None;
    let presentation = presentation_limit.is_some();
    let mut distinct = HashSet::new();
    let mut blank_count = 0usize;
    let mut has_self = false;
    for member in &group.members {
        check_cancelled(cancelled)?;
        let bytes = member.id.as_slice();
        has_self |= peer_inputs
            .active
            .as_ref()
            .is_some_and(|active| active.as_slice() == bytes);
        if presentation {
            if bytes.is_empty() {
                blank_count = blank_count
                    .checked_add(1)
                    .ok_or(RosterReadError::ResourceExhausted)?;
            } else {
                distinct
                    .try_reserve(1)
                    .map_err(|_| RosterReadError::ResourceExhausted)?;
                distinct.insert(bytes);
            }
        }
        if let Some(index) = keys.selected_index(bytes) {
            selected_hits[index / 64] |= 1u64 << (index % 64);
        }
        if !bytes.is_empty() {
            first.get_or_insert(bytes);
            let local = <[u8; 32]>::try_from(bytes)
                .is_ok_and(|id| peer_inputs.local_profile_ids.contains(&id));
            if !local {
                first_nonlocal.get_or_insert(bytes);
            }
            if peer_inputs
                .active
                .as_ref()
                .is_some_and(|active| active.as_slice() != bytes)
            {
                first_nonself.get_or_insert(bytes);
            }
        }
    }
    let chosen_peer = first_nonself.or(first_nonlocal).or(first);
    if let (Some(limit), Some(peer)) = (presentation_limit, chosen_peer)
        && peer.len().checked_mul(2).is_none_or(|bytes| bytes > limit)
    {
        return Err(RosterReadError::ResourceExhausted);
    }
    let peer = chosen_peer.map(|bytes| SelectedPeer {
        selected_key: keys.selected_index(bytes),
    });
    check_cancelled(cancelled)?;
    Ok(ProjectedRosterEvidence {
        selected_hits,
        roster_nonempty: !group.members.is_empty(),
        peer,
        active_account_is_member: peer_inputs.active.map(|_| has_self),
        unrecoverable: group.unrecoverable,
        presentation: if presentation {
            let count = distinct
                .len()
                .checked_add(blank_count)
                .ok_or(RosterReadError::ResourceExhausted)?;
            Some(SelectedRosterPresentation {
                peer_id_hex: chosen_peer.map(hex::encode),
                member_count: count.min(i32::MAX as usize) as i32,
                active_account_is_sole_member: count == 1 && has_self,
                active_account_is_member: has_self,
            })
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests;
