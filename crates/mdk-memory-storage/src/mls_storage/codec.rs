//! JSON codec for serializing/deserializing OpenMLS types to in-memory byte vectors.

use mdk_storage_traits::MdkStorageError;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// JSON codec for serializing and deserializing OpenMLS types.
///
/// This codec uses serde_json to serialize types to JSON byte arrays.
/// This matches the serialization format used by `MdkSqliteStorage` for consistency.
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
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestData {
        id: u32,
        name: String,
        bytes: Vec<u8>,
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
