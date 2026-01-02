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
        // Validate limit is within allowed range
        if !(1..=mdk_storage_traits::welcomes::MAX_PENDING_WELCOMES_LIMIT).contains(&limit) {
            return Err(WelcomeError::InvalidParameters(format!(
                "Limit must be between 1 and {}, got {}",
                mdk_storage_traits::welcomes::MAX_PENDING_WELCOMES_LIMIT,
                limit
            )));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use mdk_storage_traits::GroupId;
    use mdk_storage_traits::test_utils::cross_storage::create_test_welcome;
    use nostr::EventId;
    use openmls_memory_storage::MemoryStorage;

    #[test]
    fn test_pending_welcomes_pagination_memory() {
        let storage = MdkMemoryStorage::new(MemoryStorage::default());

        let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);

        // Create 25 pending welcomes with increasing IDs
        for i in 0..25 {
            let event_id = EventId::from_hex(&format!("{:064x}", i + 1)).unwrap();
            let welcome = create_test_welcome(mls_group_id.clone(), event_id);
            storage.save_welcome(welcome).unwrap();
        }

        // Test 1: Get all pending welcomes (should use default limit)
        let all_welcomes = storage.pending_welcomes().unwrap();
        assert_eq!(all_welcomes.len(), 25);

        // Test 2: Get first 10 welcomes
        let first_10 = storage.pending_welcomes_paginated(10, 0).unwrap();
        assert_eq!(first_10.len(), 10);

        // Test 3: Get next 10 welcomes (offset 10)
        let next_10 = storage.pending_welcomes_paginated(10, 10).unwrap();
        assert_eq!(next_10.len(), 10);

        // Test 4: Get last 5 welcomes (offset 20)
        let last_5 = storage.pending_welcomes_paginated(10, 20).unwrap();
        assert_eq!(last_5.len(), 5);

        // Test 5: Offset beyond available welcomes returns empty
        let beyond = storage.pending_welcomes_paginated(10, 30).unwrap();
        assert_eq!(beyond.len(), 0);

        // Test 6: Verify no overlap between pages
        let first_id = first_10[0].id;
        let second_page_ids: Vec<EventId> = next_10.iter().map(|w| w.id).collect();
        assert!(
            !second_page_ids.contains(&first_id),
            "Pages should not overlap"
        );

        // Test 7: Verify ordering is descending by ID
        for i in 0..first_10.len() - 1 {
            assert!(
                first_10[i].id > first_10[i + 1].id,
                "Welcomes should be ordered by ID descending"
            );
        }

        // Test 8: Limit of 0 should return error
        let result = storage.pending_welcomes_paginated(0, 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be between 1 and")
        );

        // Test 9: Limit exceeding MAX should return error
        let result = storage.pending_welcomes_paginated(20000, 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be between 1 and")
        );

        // Test 10: Empty results when no pending entries
        let storage2 = MdkMemoryStorage::new(MemoryStorage::default());
        let empty = storage2.pending_welcomes_paginated(10, 0).unwrap();
        assert_eq!(empty.len(), 0);
    }
}
