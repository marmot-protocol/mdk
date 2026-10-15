//! An in-memory catalog with the same semantics as the SQLCipher one, for
//! this crate's tests and the conformance suite. Slots stand in for message
//! attachment slots; a superseded slot refuses publication like a removed one.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::catalog::{
    CatalogError, CatalogResult, Category, ExistingOutcome, FileId, FilePresence, FileState,
    MediaCatalog, NewFile, Presence, PublishTarget, ReadyFile, ReadyOutcome,
};

struct Row {
    key: [u8; 32],
    state: FileState,
    category: Category,
    byte_len: u64,
    digest: [u8; 32],
}

#[derive(Default)]
struct State {
    rows: BTreeMap<FileId, Row>,
    refs: HashMap<u32, FileId>,
    superseded: HashSet<u32>,
}

impl State {
    /// The ready file with this content other than `except`, and its length.
    fn ready_twin(
        &self,
        category: Category,
        digest: &[u8; 32],
        except: Option<FileId>,
    ) -> Option<(FileId, u64)> {
        self.rows
            .iter()
            .find(|(id, row)| {
                Some(**id) != except
                    && row.state == FileState::Ready
                    && row.category == category
                    && &row.digest == digest
            })
            .map(|(id, row)| (*id, row.byte_len))
    }

    fn mark_lost(&mut self, id: FileId) -> bool {
        match self.rows.get_mut(&id) {
            Some(row) if row.state == FileState::Ready => {
                row.state = FileState::Lost;
                row.key = [0; 32];
                true
            }
            _ => false,
        }
    }

    /// Removing the last reference deletes a non-pending row, like the
    /// SQLCipher catalog's trigger.
    fn release(&mut self, slot: u32) -> Vec<FileId> {
        let Some(id) = self.refs.remove(&slot) else {
            return Vec::new();
        };
        let referenced = self.refs.values().any(|other| *other == id);
        let pending = self
            .rows
            .get(&id)
            .is_some_and(|row| row.state == FileState::Pending);
        if !referenced && !pending && self.rows.remove(&id).is_some() {
            return vec![id];
        }
        Vec::new()
    }

    fn attach(&mut self, slot: u32, id: FileId) {
        if self.refs.get(&slot) != Some(&id) {
            self.release(slot);
            self.refs.insert(slot, id);
        }
    }
}

#[derive(Clone, Default)]
pub struct MemoryCatalog {
    state: Arc<Mutex<State>>,
    closed: Arc<AtomicBool>,
    key_lookups: Arc<AtomicUsize>,
}

impl MemoryCatalog {
    fn state(&self) -> CatalogResult<std::sync::MutexGuard<'_, State>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CatalogError::Closed);
        }
        Ok(self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// How many times a ready file's key was looked up.
    pub fn key_lookups(&self) -> usize {
        self.key_lookups.load(Ordering::Relaxed)
    }

    /// Closes the catalog, like the account database closing.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn target(&self, slot: u32) -> MemoryTarget {
        MemoryTarget {
            catalog: self.clone(),
            slot,
        }
    }

    /// The slot stops accepting publication, like an explicit removal.
    pub fn supersede(&self, slot: u32) {
        let mut state = self.state().expect("catalog open");
        state.superseded.insert(slot);
        state.release(slot);
    }

    /// Removes the slot's reference; returns the ids whose rows it deleted.
    pub fn release(&self, slot: u32) -> Vec<FileId> {
        self.state().expect("catalog open").release(slot)
    }

    /// A store reset: every row and reference goes.
    pub fn reset(&self) {
        let mut state = self.state().expect("catalog open");
        state.rows.clear();
        state.refs.clear();
    }

    /// Deletes a row directly, as a committed key-first deletion does.
    pub fn delete_row(&self, id: FileId) {
        self.state().expect("catalog open").rows.remove(&id);
    }
}

impl MediaCatalog for MemoryCatalog {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn insert_pending(&self, file: &NewFile) -> CatalogResult<()> {
        self.state()?.rows.insert(
            file.id,
            Row {
                key: *file.key.as_bytes(),
                state: FileState::Pending,
                category: file.category,
                byte_len: file.byte_len,
                digest: file.digest,
            },
        );
        Ok(())
    }

    fn abandon_pending(&self, id: FileId) -> CatalogResult<bool> {
        let mut state = self.state()?;
        if state
            .rows
            .get(&id)
            .is_some_and(|row| row.state == FileState::Pending)
        {
            state.rows.remove(&id);
            return Ok(true);
        }
        Ok(false)
    }

    fn ready_file(&self, id: FileId) -> CatalogResult<Option<ReadyFile>> {
        self.key_lookups.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .state()?
            .rows
            .get(&id)
            .filter(|row| row.state == FileState::Ready)
            .and_then(|row| ReadyFile::from_key_bytes(&row.key, row.byte_len)))
    }

    fn file_state(&self, id: FileId) -> CatalogResult<Option<FileState>> {
        Ok(self.state()?.rows.get(&id).map(|row| row.state))
    }

    fn mark_lost(&self, id: FileId) -> CatalogResult<bool> {
        Ok(self.state()?.mark_lost(id))
    }

    fn page(&self, after: Option<FileId>, limit: usize) -> CatalogResult<Vec<(FileId, FileState)>> {
        let state = self.state()?;
        Ok(state
            .rows
            .iter()
            .filter(|(id, _)| after.is_none_or(|after| **id > after))
            .take(limit)
            .map(|(id, row)| (*id, row.state))
            .collect())
    }
}

/// Publication into one slot of a `MemoryCatalog`.
pub struct MemoryTarget {
    catalog: MemoryCatalog,
    slot: u32,
}

impl PublishTarget for MemoryTarget {
    fn superseded(&self) -> CatalogResult<bool> {
        Ok(self.catalog.state()?.superseded.contains(&self.slot))
    }

    fn commit_existing(
        &self,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ExistingOutcome> {
        let mut state = self.catalog.state()?;
        let Some((twin, byte_len)) = state.ready_twin(category, digest, None) else {
            return Ok(ExistingOutcome::None);
        };
        if present(twin, byte_len)? == FilePresence::Absent {
            state.mark_lost(twin);
            return Ok(ExistingOutcome::None);
        }
        if state.superseded.contains(&self.slot) {
            return Ok(ExistingOutcome::Superseded);
        }
        state.attach(self.slot, twin);
        Ok(ExistingOutcome::Attached(twin))
    }

    fn commit_ready(
        &self,
        id: FileId,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ReadyOutcome> {
        let mut state = self.catalog.state()?;
        if !state
            .rows
            .get(&id)
            .is_some_and(|row| row.state == FileState::Pending)
        {
            return Ok(ReadyOutcome::Superseded);
        }
        if state.superseded.contains(&self.slot) {
            return Ok(ReadyOutcome::Superseded);
        }
        if let Some((twin, byte_len)) = state.ready_twin(category, digest, Some(id)) {
            if present(twin, byte_len)? == FilePresence::Present {
                state.rows.remove(&id);
                state.attach(self.slot, twin);
                return Ok(ReadyOutcome::Existing(twin));
            }
            state.mark_lost(twin);
        }
        if let Some(row) = state.rows.get_mut(&id) {
            row.state = FileState::Ready;
        }
        state.attach(self.slot, id);
        Ok(ReadyOutcome::Ready)
    }
}
