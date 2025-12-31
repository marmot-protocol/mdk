//! Input validation constants and utilities for SQLite storage.
//!
//! These limits prevent unbounded user input from causing disk and CPU exhaustion.

/// Maximum size for message content (1 MB)
pub const MAX_MESSAGE_CONTENT_SIZE: usize = 1024 * 1024;

/// Maximum size for serialized tags JSON (100 KB)
pub const MAX_TAGS_JSON_SIZE: usize = 100 * 1024;

/// Maximum size for serialized event JSON (100 KB)
pub const MAX_EVENT_JSON_SIZE: usize = 100 * 1024;

/// Maximum length for group name (255 characters)
pub const MAX_GROUP_NAME_LENGTH: usize = 255;

/// Maximum length for group description (2000 characters)
pub const MAX_GROUP_DESCRIPTION_LENGTH: usize = 2000;

/// Maximum size for serialized admin pubkeys JSON (50 KB)
pub const MAX_ADMIN_PUBKEYS_JSON_SIZE: usize = 50 * 1024;

/// Maximum size for serialized group relays JSON (50 KB)
pub const MAX_GROUP_RELAYS_JSON_SIZE: usize = 50 * 1024;

/// Validate that a byte slice does not exceed the specified maximum size.
#[inline]
pub fn validate_size(data: &[u8], max_size: usize, field_name: &str) -> Result<(), String> {
    if data.len() > max_size {
        return Err(format!(
            "{} exceeds maximum size of {} bytes (got {} bytes)",
            field_name,
            max_size,
            data.len()
        ));
    }
    Ok(())
}

/// Validate that a string does not exceed the specified maximum length.
#[inline]
pub fn validate_string_length(s: &str, max_length: usize, field_name: &str) -> Result<(), String> {
    if s.len() > max_length {
        return Err(format!(
            "{} exceeds maximum length of {} characters (got {} characters)",
            field_name,
            max_length,
            s.len()
        ));
    }
    Ok(())
}
