//! Memory-based storage implementation of the MdkStorageProvider trait for Nostr MLS welcomes

use mdk_storage_traits::welcomes::WelcomeStorage;
use mdk_storage_traits::welcomes::error::WelcomeError;
use mdk_storage_traits::welcomes::types::*;
use nostr::EventId;

use crate::MdkMemoryStorage;

impl WelcomeStorage for MdkMemoryStorage {
    fn save_welcome(&self, welcome: Welcome) -> Result<(), WelcomeError> {
        let mut cache = self.welcomes_cache.write();
        cache.put(welcome.id, welcome);

        Ok(())
    }

    fn pending_welcomes_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Welcome>, WelcomeError> {
        let cache = self.welcomes_cache.read();
        let mut welcomes: Vec<Welcome> = cache
            .iter()
            .map(|(_, v)| v.clone())
            .filter(|welcome| welcome.state == WelcomeState::Pending)
            .collect();

        // Sort by ID (descending) for consistent ordering
        welcomes.sort_by(|a, b| b.id.cmp(&a.id));

        // Apply pagination
        let welcomes: Vec<Welcome> = welcomes.into_iter().skip(offset).take(limit).collect();

        Ok(welcomes)
    }

    fn find_welcome_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<Welcome>, WelcomeError> {
        let cache = self.welcomes_cache.read();
        Ok(cache.peek(event_id).cloned())
    }

    fn save_processed_welcome(
        &self,
        processed_welcome: ProcessedWelcome,
    ) -> Result<(), WelcomeError> {
        let mut cache = self.processed_welcomes_cache.write();
        cache.put(processed_welcome.wrapper_event_id, processed_welcome);

        Ok(())
    }

    fn find_processed_welcome_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<ProcessedWelcome>, WelcomeError> {
        let cache = self.processed_welcomes_cache.read();
        Ok(cache.peek(event_id).cloned())
    }
}
