//! Group storage test functions

use std::collections::BTreeSet;

use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::GroupStorage;
use mdk_storage_traits::groups::error::GroupError;
use mdk_storage_traits::groups::types::GroupExporterSecret;
use nostr::{PublicKey, RelayUrl};

use super::create_test_group;

/// Test basic group save and find functionality
pub fn test_save_and_find_group<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 6]);
    let group = create_test_group(mls_group_id.clone());

    // Test save
    storage.save_group(group.clone()).unwrap();

    // Test find by MLS group ID
    let found_group = storage.find_group_by_mls_group_id(&mls_group_id).unwrap();
    assert!(found_group.is_some());
    let found_group = found_group.unwrap();
    assert_eq!(found_group.mls_group_id, group.mls_group_id);
    assert_eq!(found_group.nostr_group_id, group.nostr_group_id);
    assert_eq!(found_group.name, group.name);
    assert_eq!(found_group.description, group.description);

    // Test find by Nostr group ID
    let found_group = storage
        .find_group_by_nostr_group_id(&group.nostr_group_id)
        .unwrap();
    assert!(found_group.is_some());
    let found_group = found_group.unwrap();
    assert_eq!(found_group.mls_group_id, group.mls_group_id);

    // Test find non-existent group
    let non_existent_id = GroupId::from_slice(&[99, 99, 99, 99]);
    let result = storage
        .find_group_by_mls_group_id(&non_existent_id)
        .unwrap();
    assert!(result.is_none());
}

/// Test all groups functionality
pub fn test_all_groups<S>(storage: S)
where
    S: GroupStorage,
{
    // Initially should be empty
    let groups = storage.all_groups().unwrap();
    assert_eq!(groups.len(), 0);

    // Add some groups
    let group1 = create_test_group(GroupId::from_slice(&[1, 2, 3, 8]));
    let group2 = create_test_group(GroupId::from_slice(&[1, 2, 3, 9]));
    let group3 = create_test_group(GroupId::from_slice(&[1, 2, 3, 10]));

    storage.save_group(group1.clone()).unwrap();
    storage.save_group(group2.clone()).unwrap();
    storage.save_group(group3.clone()).unwrap();

    // Test all groups
    let groups = storage.all_groups().unwrap();
    assert_eq!(groups.len(), 3);

    let group_ids: BTreeSet<_> = groups.iter().map(|g| g.mls_group_id.clone()).collect();
    assert!(group_ids.contains(&group1.mls_group_id));
    assert!(group_ids.contains(&group2.mls_group_id));
    assert!(group_ids.contains(&group3.mls_group_id));
}

/// Test group exporter secret functionality
pub fn test_group_exporter_secret<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 7]);
    let group = create_test_group(mls_group_id.clone());
    storage.save_group(group).unwrap();

    let epoch = 42u64;
    let secret = [0x42u8; 32];
    let exporter_secret = GroupExporterSecret {
        mls_group_id: mls_group_id.clone(),
        epoch,
        secret,
    };

    // Test save
    storage
        .save_group_exporter_secret(exporter_secret.clone())
        .unwrap();

    // Test get
    let retrieved = storage
        .get_group_exporter_secret(&mls_group_id, epoch)
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.mls_group_id, mls_group_id);
    assert_eq!(retrieved.epoch, epoch);
    assert_eq!(retrieved.secret, secret);

    // Test get non-existent
    let result = storage
        .get_group_exporter_secret(&mls_group_id, 999)
        .unwrap();
    assert!(result.is_none());
}

/// Test basic group relay functionality (not the comprehensive replace tests)
pub fn test_basic_group_relays<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 11]);
    let group = create_test_group(mls_group_id.clone());
    storage.save_group(group).unwrap();

    // Initially should be empty
    let relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(relays.len(), 0);

    // Add a relay using replace
    let relay_url = RelayUrl::parse("wss://relay.example.com").unwrap();
    let relays_set = BTreeSet::from([relay_url.clone()]);
    storage
        .replace_group_relays(&mls_group_id, relays_set)
        .unwrap();

    // Verify it's there
    let relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays.first().unwrap().relay_url, relay_url);
}

/// Test comprehensive relay replacement functionality
pub fn test_replace_group_relays_comprehensive<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);
    let group = create_test_group(mls_group_id.clone());

    // Save the test group
    storage.save_group(group).unwrap();

    // Test 1: Replace with initial relay set
    let relay1 = RelayUrl::parse("wss://relay1.example.com").unwrap();
    let relay2 = RelayUrl::parse("wss://relay2.example.com").unwrap();
    let initial_relays = BTreeSet::from([relay1.clone(), relay2.clone()]);

    storage
        .replace_group_relays(&mls_group_id, initial_relays.clone())
        .unwrap();
    let stored_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored_relays.len(), 2);
    assert!(stored_relays.iter().any(|r| r.relay_url == relay1));
    assert!(stored_relays.iter().any(|r| r.relay_url == relay2));

    // Test 2: Replace with different relay set (should remove old ones)
    let relay3 = RelayUrl::parse("wss://relay3.example.com").unwrap();
    let relay4 = RelayUrl::parse("wss://relay4.example.com").unwrap();
    let new_relays = BTreeSet::from([relay3.clone(), relay4.clone()]);

    storage
        .replace_group_relays(&mls_group_id, new_relays.clone())
        .unwrap();
    let stored_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored_relays.len(), 2);
    assert!(stored_relays.iter().any(|r| r.relay_url == relay3));
    assert!(stored_relays.iter().any(|r| r.relay_url == relay4));
    // Old relays should be gone
    assert!(!stored_relays.iter().any(|r| r.relay_url == relay1));
    assert!(!stored_relays.iter().any(|r| r.relay_url == relay2));

    // Test 3: Replace with empty set
    storage
        .replace_group_relays(&mls_group_id, BTreeSet::new())
        .unwrap();
    let stored_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored_relays.len(), 0);

    // Test 4: Replace with single relay after empty
    let single_relay = BTreeSet::from([relay1.clone()]);
    storage
        .replace_group_relays(&mls_group_id, single_relay)
        .unwrap();
    let stored_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored_relays.len(), 1);
    assert_eq!(stored_relays.first().unwrap().relay_url, relay1);

    // Test 5: Replace with large set
    let large_set: BTreeSet<RelayUrl> = (1..=10)
        .map(|i| RelayUrl::parse(&format!("wss://relay{}.example.com", i)).unwrap())
        .collect();
    storage
        .replace_group_relays(&mls_group_id, large_set.clone())
        .unwrap();
    let stored_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored_relays.len(), 10);
    for expected_relay in &large_set {
        assert!(stored_relays.iter().any(|r| r.relay_url == *expected_relay));
    }
}

/// Test error cases for relay replacement
pub fn test_replace_group_relays_error_cases<S>(storage: S)
where
    S: GroupStorage,
{
    // Test: Replace relays for non-existent group
    let non_existent_group_id = GroupId::from_slice(&[99, 99, 99, 99]);
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let relays = BTreeSet::from([relay]);

    let result = storage.replace_group_relays(&non_existent_group_id, relays);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GroupError::InvalidParameters(_)
    ));
}

/// Test duplicate handling for replace_group_relays
pub fn test_replace_group_relays_duplicate_handling<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 5]);
    let group = create_test_group(mls_group_id.clone());

    storage.save_group(group).unwrap();

    // Test: BTreeSet naturally handles duplicates, but test behavior is consistent
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let relays = BTreeSet::from([relay.clone()]);

    // Add same relay multiple times - should be idempotent
    storage
        .replace_group_relays(&mls_group_id, relays.clone())
        .unwrap();
    storage
        .replace_group_relays(&mls_group_id, relays.clone())
        .unwrap();

    let stored_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored_relays.len(), 1);
    assert_eq!(stored_relays.first().unwrap().relay_url, relay);
}

/// Test edge cases and error conditions for group operations
pub fn test_group_edge_cases<S>(storage: S)
where
    S: GroupStorage,
{
    // Test saving group with empty name
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 14]);
    let mut group = create_test_group(mls_group_id.clone());
    group.name = String::new();

    // Should still work (empty names are valid)
    storage.save_group(group.clone()).unwrap();
    let found = storage
        .find_group_by_mls_group_id(&mls_group_id)
        .unwrap()
        .unwrap();
    assert_eq!(found.name, "");

    // Test saving group with long name (within limits)
    let long_name = "a".repeat(250); // Within 255 byte limit
    group.name = long_name.clone();
    storage.save_group(group).unwrap();
    let found = storage
        .find_group_by_mls_group_id(&mls_group_id)
        .unwrap()
        .unwrap();
    assert_eq!(found.name, long_name);

    // Test duplicate group save (should update existing)
    let mut updated_group = create_test_group(mls_group_id.clone());
    updated_group.description = "Updated description".to_string();
    storage.save_group(updated_group).unwrap();
    let found = storage
        .find_group_by_mls_group_id(&mls_group_id)
        .unwrap()
        .unwrap();
    assert_eq!(found.description, "Updated description");
}

/// Test concurrent relay operations and edge cases
pub fn test_replace_relays_edge_cases<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 15]);
    let group = create_test_group(mls_group_id.clone());
    storage.save_group(group).unwrap();

    // Test with very large relay sets
    let large_relay_set: BTreeSet<RelayUrl> = (1..=100)
        .map(|i| RelayUrl::parse(&format!("wss://relay{}.example.com", i)).unwrap())
        .collect();

    storage
        .replace_group_relays(&mls_group_id, large_relay_set.clone())
        .unwrap();
    let stored = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(stored.len(), 100);

    // Test multiple rapid replacements
    for i in 0..10 {
        let relay_set = BTreeSet::from([RelayUrl::parse(&format!("wss://test{}.com", i)).unwrap()]);
        storage
            .replace_group_relays(&mls_group_id, relay_set)
            .unwrap();
    }
    let final_relays = storage.group_relays(&mls_group_id).unwrap();
    assert_eq!(final_relays.len(), 1);
    assert_eq!(
        final_relays.first().unwrap().relay_url.to_string(),
        "wss://test9.com"
    );
}

/// Test message storage functionality with group queries
pub fn test_messages_for_group<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 12]);
    let group = create_test_group(mls_group_id.clone());
    storage.save_group(group).unwrap();

    // Test messages for group (initially empty)
    let messages = storage.messages(&mls_group_id).unwrap();
    assert_eq!(messages.len(), 0);
}

/// Test admins() functionality
pub fn test_admins<S>(storage: S)
where
    S: GroupStorage,
{
    let mls_group_id = GroupId::from_slice(&[1, 2, 3, 16]);
    let mut group = create_test_group(mls_group_id.clone());

    // Add some admins to the group using from_slice with valid 32-byte arrays
    let admin1 = PublicKey::from_slice(&[
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ])
    .unwrap();
    let admin2 = PublicKey::from_slice(&[
        0x8a, 0x9d, 0xe5, 0x62, 0xcb, 0xbe, 0xd2, 0x25, 0xb6, 0xea, 0x01, 0x18, 0xdd, 0x39, 0x97,
        0xa0, 0x2d, 0xf9, 0x2c, 0x0b, 0xff, 0xd2, 0x22, 0x4f, 0x71, 0x08, 0x1a, 0x74, 0x50, 0xc3,
        0xe5, 0x49,
    ])
    .unwrap();
    group.admin_pubkeys.insert(admin1);
    group.admin_pubkeys.insert(admin2);

    storage.save_group(group).unwrap();

    // Test getting admins for existing group
    let admins = storage.admins(&mls_group_id).unwrap();
    assert_eq!(admins.len(), 2);
    assert!(admins.contains(&admin1));
    assert!(admins.contains(&admin2));
}

/// Test admins() returns error for non-existent group
pub fn test_admins_error_for_nonexistent_group<S>(storage: S)
where
    S: GroupStorage,
{
    let non_existent_id = GroupId::from_slice(&[99, 99, 99, 17]);

    let result = storage.admins(&non_existent_id);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GroupError::InvalidParameters(_)
    ));
}

/// Test messages() returns error for non-existent group
pub fn test_messages_error_for_nonexistent_group<S>(storage: S)
where
    S: GroupStorage,
{
    let non_existent_id = GroupId::from_slice(&[99, 99, 99, 18]);

    let result = storage.messages(&non_existent_id);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GroupError::InvalidParameters(_)
    ));
}

/// Test group_relays() returns error for non-existent group
pub fn test_group_relays_error_for_nonexistent_group<S>(storage: S)
where
    S: GroupStorage,
{
    let non_existent_id = GroupId::from_slice(&[99, 99, 99, 19]);

    let result = storage.group_relays(&non_existent_id);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GroupError::InvalidParameters(_)
    ));
}
