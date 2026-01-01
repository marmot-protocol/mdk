//! Input validation constants and utilities for SQLite storage.
//!
//! These limits prevent unbounded user input from causing disk and CPU exhaustion.

use crate::error::Error;

/// Maximum size for message content (1 MB)
pub const MAX_MESSAGE_CONTENT_SIZE: usize = 1024 * 1024;

/// Maximum size for serialized tags JSON (100 KB)
pub const MAX_TAGS_JSON_SIZE: usize = 100 * 1024;

/// Maximum size for serialized event JSON (100 KB)
pub const MAX_EVENT_JSON_SIZE: usize = 100 * 1024;

/// Maximum length for group name (255 bytes, UTF-8 encoded)
pub const MAX_GROUP_NAME_LENGTH: usize = 255;

/// Maximum length for group description (2000 bytes, UTF-8 encoded)
pub const MAX_GROUP_DESCRIPTION_LENGTH: usize = 2000;

/// Maximum size for serialized admin pubkeys JSON (50 KB)
pub const MAX_ADMIN_PUBKEYS_JSON_SIZE: usize = 50 * 1024;

/// Maximum size for serialized group relays JSON (50 KB)
pub const MAX_GROUP_RELAYS_JSON_SIZE: usize = 50 * 1024;

/// Validate that a byte slice does not exceed the specified maximum size.
#[inline]
pub fn validate_size(data: &[u8], max_size: usize, field_name: &str) -> Result<(), Error> {
    if data.len() > max_size {
        return Err(Error::Validation {
            field_name: field_name.to_string(),
            max_size,
            actual_size: data.len(),
        });
    }
    Ok(())
}

/// Validate that a string does not exceed the specified maximum length in bytes.
///
/// Note: This validates UTF-8 byte length, not Unicode character count.
/// Multi-byte characters (e.g., emoji) will count as multiple bytes.
#[inline]
pub fn validate_string_length(s: &str, max_length: usize, field_name: &str) -> Result<(), Error> {
    if s.len() > max_length {
        return Err(Error::Validation {
            field_name: field_name.to_string(),
            max_size: max_length,
            actual_size: s.len(),
        });
    }
    Ok(())
}
