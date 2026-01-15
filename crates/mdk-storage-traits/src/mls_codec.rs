//! MLS codec and types for storage implementations.
//!
//! This module provides shared codec and type definitions used by both
//! memory and SQLite storage implementations for OpenMLS data.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::MdkStorageError;

/// The storage provider version matching OpenMLS's CURRENT_VERSION.
pub const STORAGE_PROVIDER_VERSION: u16 = 1;

/// Types of group data stored in MLS storage.
///
/// This enum represents the different types of MLS group data that can be stored.
/// Both in-memory and SQLite storage implementations use this to distinguish
/// between different data types associated with a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupDataType {
    /// MLS group join configuration
    JoinGroupConfig,
    /// TreeSync tree structure
    Tree,
    /// Interim transcript hash
    InterimTranscriptHash,
    /// Group context
    Context,
    /// Confirmation tag
    ConfirmationTag,
    /// Group state (active, inactive, etc.)
    GroupState,
    /// Message secrets for decryption
    MessageSecrets,
    /// Resumption PSK store
    ResumptionPskStore,
    /// Own leaf index in the tree
    OwnLeafIndex,
    /// Group epoch secrets
    GroupEpochSecrets,
}

impl GroupDataType {
    /// Convert to string for database storage.
    ///
    /// This method returns a stable string representation suitable for
    /// use as a database key or column value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JoinGroupConfig => "join_group_config",
            Self::Tree => "tree",
            Self::InterimTranscriptHash => "interim_transcript_hash",
            Self::Context => "context",
            Self::ConfirmationTag => "confirmation_tag",
            Self::GroupState => "group_state",
            Self::MessageSecrets => "message_secrets",
            Self::ResumptionPskStore => "resumption_psk_store",
            Self::OwnLeafIndex => "own_leaf_index",
            Self::GroupEpochSecrets => "group_epoch_secrets",
        }
    }
}

/// JSON codec for serializing and deserializing OpenMLS types.
///
/// This codec uses serde_json to serialize types to JSON byte arrays.
/// It is used by both memory and SQLite storage implementations to ensure
/// consistent serialization format across storage backends.
pub struct JsonCodec;

impl JsonCodec {
    /// Serialize a value to a JSON byte vector.
    ///
    /// # Errors
    ///
    /// Returns `MdkStorageError::Serialization` if serialization fails.
    #[inline]
    pub fn serialize<T>(value: &T) -> Result<Vec<u8>, MdkStorageError>
    where
        T: Serialize,
    {
        serde_json::to_vec(value).map_err(|e| MdkStorageError::Serialization(e.to_string()))
    }

    /// Deserialize a value from a JSON byte slice.
    ///
    /// # Errors
    ///
    /// Returns `MdkStorageError::Deserialization` if deserialization fails.
    #[inline]
    pub fn deserialize<T>(slice: &[u8]) -> Result<T, MdkStorageError>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(slice).map_err(|e| MdkStorageError::Deserialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestData {
        id: u32,
        name: String,
        bytes: Vec<u8>,
    }

    #[test]
    fn test_group_data_type_as_str() {
        assert_eq!(GroupDataType::JoinGroupConfig.as_str(), "join_group_config");
        assert_eq!(GroupDataType::Tree.as_str(), "tree");
        assert_eq!(
            GroupDataType::InterimTranscriptHash.as_str(),
            "interim_transcript_hash"
        );
        assert_eq!(GroupDataType::Context.as_str(), "context");
        assert_eq!(GroupDataType::ConfirmationTag.as_str(), "confirmation_tag");
        assert_eq!(GroupDataType::GroupState.as_str(), "group_state");
        assert_eq!(GroupDataType::MessageSecrets.as_str(), "message_secrets");
        assert_eq!(
            GroupDataType::ResumptionPskStore.as_str(),
            "resumption_psk_store"
        );
        assert_eq!(GroupDataType::OwnLeafIndex.as_str(), "own_leaf_index");
        assert_eq!(
            GroupDataType::GroupEpochSecrets.as_str(),
            "group_epoch_secrets"
        );
    }

    #[test]
    fn test_group_data_type_equality() {
        assert_eq!(
            GroupDataType::JoinGroupConfig,
            GroupDataType::JoinGroupConfig
        );
        assert_ne!(GroupDataType::JoinGroupConfig, GroupDataType::Tree);
    }

    #[test]
    fn test_group_data_type_hash() {
        let mut set = HashSet::new();
        set.insert(GroupDataType::Tree);
        set.insert(GroupDataType::Context);
        set.insert(GroupDataType::Tree); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&GroupDataType::Tree));
        assert!(set.contains(&GroupDataType::Context));
    }

    #[test]
    fn test_roundtrip_simple() {
        let original = TestData {
            id: 42,
            name: "test".to_string(),
            bytes: vec![1, 2, 3, 4],
        };

        let serialized = JsonCodec::serialize(&original).unwrap();
        let deserialized: TestData = JsonCodec::deserialize(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_roundtrip_empty_bytes() {
        let original = TestData {
            id: 0,
            name: String::new(),
            bytes: vec![],
        };

        let serialized = JsonCodec::serialize(&original).unwrap();
        let deserialized: TestData = JsonCodec::deserialize(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_roundtrip_large_bytes() {
        let original = TestData {
            id: u32::MAX,
            name: "x".repeat(10000),
            bytes: vec![0xFFu8; 10000],
        };

        let serialized = JsonCodec::serialize(&original).unwrap();
        let deserialized: TestData = JsonCodec::deserialize(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_deserialize_invalid_json() {
        let invalid = b"not valid json";
        let result: Result<TestData, _> = JsonCodec::deserialize(invalid);

        assert!(result.is_err());
        match result {
            Err(MdkStorageError::Deserialization(msg)) => {
                assert!(msg.contains("expected"));
            }
            _ => panic!("Expected Deserialization error"),
        }
    }

    #[test]
    fn test_deserialize_wrong_type() {
        let wrong_type = r#"{"wrong": "structure"}"#.as_bytes();
        let result: Result<TestData, _> = JsonCodec::deserialize(wrong_type);

        assert!(result.is_err());
        match result {
            Err(MdkStorageError::Deserialization(_)) => {}
            _ => panic!("Expected Deserialization error"),
        }
    }
}
