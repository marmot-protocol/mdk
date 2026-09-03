use std::fmt;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::message::MessageState;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::EpochId;
use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Total bind-parameter budget for generated statements that use chunked
/// positive-`IN` lists. This stays below SQLite's historical 999-variable
/// default and includes any fixed parameters that precede the list.
pub(crate) const SQLITE_BIND_PARAMETER_CHUNK: usize = 900;

/// Bytes whose current allocation is wiped when ownership ends.
///
/// JSON deserialization grows this buffer explicitly so each replaced
/// allocation is zeroized before deallocation. The storage backend is JSON-only;
/// deliberately accepting only sequence input avoids a binary deserializer
/// constructing an intermediate ordinary `Vec<u8>` before this type takes over.
pub(crate) struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn push(&mut self, byte: u8) {
        if self.0.len() == self.0.capacity() {
            let next_capacity = if self.0.capacity() == 0 {
                8
            } else {
                self.0
                    .capacity()
                    .checked_mul(2)
                    .expect("sensitive byte buffer capacity overflow")
            };
            let mut next = Zeroizing::new(Vec::with_capacity(next_capacity));
            next.extend_from_slice(self.0.as_slice());
            let previous = std::mem::replace(&mut self.0, next);
            drop(previous);
        }
        self.0.push(byte);
    }

    pub(crate) fn extend_exact(&mut self, bytes: &[u8]) -> StorageResult<()> {
        if bytes.len() > self.0.capacity().saturating_sub(self.0.len()) {
            return Err(StorageError::Serialization(
                "sensitive binary encoding exceeded its exact allocation".to_owned(),
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl Write for SensitiveBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for byte in bytes {
            self.push(*byte);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Serialize for SensitiveBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SensitiveBytesVisitor;

        impl<'de> Visitor<'de> for SensitiveBytesVisitor {
            type Value = SensitiveBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON byte array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = SensitiveBytes::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_seq(SensitiveBytesVisitor)
    }
}

#[derive(Default)]
struct JsonLength {
    bytes: usize,
}

impl Write for JsonLength {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("sensitive JSON length overflow"))?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct SensitiveJsonWriter {
    bytes: SensitiveBytes,
    limit: usize,
}

impl SensitiveJsonWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: SensitiveBytes::with_capacity(capacity),
            limit: capacity,
        }
    }

    fn into_bytes(self) -> SensitiveBytes {
        self.bytes
    }
}

impl Write for SensitiveJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let remaining = self.limit - self.bytes.0.len();
        if bytes.len() > remaining {
            return Err(io::Error::other(
                "sensitive JSON changed size between serialization passes",
            ));
        }
        self.bytes.0.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialize<T: Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) fn serialize_sensitive_json<T: Serialize + ?Sized>(
    value: &T,
) -> serde_json::Result<SensitiveBytes> {
    // The first pass counts bytes without retaining them. The second pass writes
    // into a fixed-capacity zeroizing allocation and fails rather than growing
    // if a stateful Serialize implementation produces a larger document.
    let mut length = JsonLength::default();
    serde_json::to_writer(&mut length, value)?;
    let mut writer = SensitiveJsonWriter::with_capacity(length.bytes);
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.into_bytes())
}

pub(crate) fn serialize_sensitive<T: Serialize + ?Sized>(
    value: &T,
) -> StorageResult<SensitiveBytes> {
    serialize_sensitive_json(value).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) trait SqliteResultExt<T> {
    fn storage(self) -> StorageResult<T>;
}

impl<T> SqliteResultExt<T> for rusqlite::Result<T> {
    fn storage(self) -> StorageResult<T> {
        self.map_err(map_sqlite_error)
    }
}

/// Map a `rusqlite::Error` to a [`StorageError`], classifying transient lock
/// contention (`SQLITE_BUSY` / `SQLITE_LOCKED`, including their extended result
/// codes) as [`StorageError::Busy`] rather than the catch-all
/// [`StorageError::Backend`]. This is the single place where the SQLite error
/// vocabulary is translated, so the transient/fatal distinction (issue #484)
/// stays in one spot and never has to be re-derived by string-parsing
/// "database is locked".
pub(crate) fn map_sqlite_error(error: rusqlite::Error) -> StorageError {
    if is_busy_error(&error) {
        StorageError::Busy(error.to_string())
    } else {
        StorageError::Backend(error.to_string())
    }
}

/// Whether a `rusqlite::Error` is transient SQLite lock contention worth
/// retrying: `SQLITE_BUSY` (the writer could not acquire the database lock
/// before the busy timeout) or `SQLITE_LOCKED` (a table in the same connection
/// is locked). Extended result codes such as `SQLITE_BUSY_RECOVERY` and
/// `SQLITE_LOCKED_SHAREDCACHE` collapse to these primary codes via
/// `sqlite_error_code`, so matching the primary codes covers them too.
pub(crate) fn is_busy_error(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

pub(crate) fn message_state_to_i64(state: MessageState) -> i64 {
    match state {
        MessageState::Sent => 0,
        MessageState::Created => 1,
        MessageState::Processed => 2,
        MessageState::Failed => 3,
        MessageState::Retryable => 4,
        MessageState::EpochInvalidated => 5,
        MessageState::PeelDeferred => 6,
        MessageState::ConvergenceDeferred => 7,
    }
}

pub(crate) fn message_state_from_i64(state: i64) -> StorageResult<MessageState> {
    match state {
        0 => Ok(MessageState::Sent),
        1 => Ok(MessageState::Created),
        2 => Ok(MessageState::Processed),
        3 => Ok(MessageState::Failed),
        4 => Ok(MessageState::Retryable),
        5 => Ok(MessageState::EpochInvalidated),
        6 => Ok(MessageState::PeelDeferred),
        7 => Ok(MessageState::ConvergenceDeferred),
        _ => Err(StorageError::Serialization(format!(
            "unknown stored message state {state}"
        ))),
    }
}

pub(crate) fn epoch_to_i64(epoch: EpochId) -> StorageResult<i64> {
    i64::try_from(epoch.0)
        .map_err(|_| StorageError::Serialization(format!("epoch too large: {}", epoch.0)))
}

pub(crate) fn created_at_to_i64(created_at_ms: u64) -> StorageResult<i64> {
    i64::try_from(created_at_ms).map_err(|_| {
        StorageError::Serialization(format!("created_at_ms too large: {created_at_ms}"))
    })
}

/// Encode a `bool` as the SQLite integer convention (`1`/`0`).
pub(crate) fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

/// Convert a `u64` to SQLite's signed `INTEGER`, erroring if it overflows `i64`.
pub(crate) fn u64_to_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

/// Convert SQLite's signed `INTEGER` to `u64`, rejecting negative values.
pub(crate) fn i64_to_u64(value: i64) -> StorageResult<u64> {
    u64::try_from(value)
        .map_err(|_| StorageError::Serialization(format!("value does not fit in u64: {value}")))
}

/// Convert SQLite's signed `INTEGER` to `usize`, rejecting negative or
/// platform-oversized values.
pub(crate) fn i64_to_usize(value: i64) -> StorageResult<usize> {
    usize::try_from(value)
        .map_err(|_| StorageError::Serialization(format!("value does not fit in usize: {value}")))
}

/// Convert an optional `u64` to SQLite's signed `INTEGER`, preserving `None`.
pub(crate) fn optional_u64_to_i64(value: Option<u64>) -> StorageResult<Option<i64>> {
    value.map(u64_to_i64).transpose()
}

/// Convert a `usize` to SQLite's signed `INTEGER`, erroring if it overflows `i64`.
pub(crate) fn usize_to_i64(value: usize) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

/// Decode a JSON tag array as stored in projection rows.
pub(crate) fn tags_from_json(json: String) -> Result<Vec<Vec<String>>, serde_json::Error> {
    serde_json::from_str(&json)
}

/// Current wall-clock milliseconds since the Unix epoch, saturating at `i64::MAX`.
pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

/// Current wall-clock seconds since the Unix epoch.
pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current wall-clock seconds since the Unix epoch, saturating at `i64::MAX`.
pub(crate) fn unix_now_seconds_i64() -> i64 {
    i64::try_from(unix_now_seconds()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct ExpandsBetweenSerializationPasses(Cell<bool>);

    impl Serialize for ExpandsBetweenSerializationPasses {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            if self.0.replace(false) {
                serializer.serialize_str("short")
            } else {
                serializer.serialize_str(
                    "a second serialization pass must not grow the sensitive allocation",
                )
            }
        }
    }

    #[test]
    fn sensitive_json_rejects_second_pass_growth_instead_of_reallocating() {
        let value = ExpandsBetweenSerializationPasses(Cell::new(true));
        let error = match serialize_sensitive(&value) {
            Ok(_) => panic!("second pass unexpectedly grew the sensitive allocation"),
            Err(error) => error,
        };

        assert!(
            matches!(error, StorageError::Serialization(message) if message.contains("sensitive JSON changed size"))
        );
    }

    #[test]
    fn sensitive_bytes_round_trip_large_json_array_without_format_change() {
        let value = vec![0xa5; 4_096];
        let encoded = serialize_sensitive(&value).unwrap();

        assert_eq!(encoded.as_slice(), serde_json::to_vec(&value).unwrap());
        let decoded: SensitiveBytes = deserialize(encoded.as_slice()).unwrap();
        assert_eq!(decoded.as_slice(), value);
    }

    fn sqlite_failure(primary: std::os::raw::c_int) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(primary),
            Some("database is locked".to_string()),
        )
    }

    #[test]
    fn busy_and_locked_are_classified_transient() {
        assert!(is_busy_error(&sqlite_failure(rusqlite::ffi::SQLITE_BUSY)));
        assert!(is_busy_error(&sqlite_failure(rusqlite::ffi::SQLITE_LOCKED)));
        // Extended result codes collapse to the primary code via
        // `sqlite_error_code`, so they classify as transient too.
        assert!(is_busy_error(&sqlite_failure(
            rusqlite::ffi::SQLITE_BUSY_RECOVERY
        )));
        assert!(is_busy_error(&sqlite_failure(
            rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE
        )));
    }

    #[test]
    fn other_sqlite_errors_are_not_transient() {
        assert!(!is_busy_error(&sqlite_failure(
            rusqlite::ffi::SQLITE_CORRUPT
        )));
        assert!(!is_busy_error(&sqlite_failure(rusqlite::ffi::SQLITE_FULL)));
        assert!(!is_busy_error(&rusqlite::Error::QueryReturnedNoRows));
    }

    #[test]
    fn map_sqlite_error_routes_busy_to_busy_variant() {
        let mapped = map_sqlite_error(sqlite_failure(rusqlite::ffi::SQLITE_BUSY));
        assert!(
            matches!(mapped, StorageError::Busy(_)),
            "SQLITE_BUSY must map to StorageError::Busy, got {mapped:?}"
        );
        assert!(mapped.is_transient());
    }

    #[test]
    fn map_sqlite_error_routes_other_errors_to_backend() {
        let mapped = map_sqlite_error(sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT));
        assert!(
            matches!(mapped, StorageError::Backend(_)),
            "non-busy errors must map to StorageError::Backend, got {mapped:?}"
        );
        assert!(!mapped.is_transient());
    }
}
