//! C mirrors of the message conversions (`marmot-uniffi/src/conversions/message.rs`):
//! stored message records, secure-delete results, and the unified
//! message-subscription update payload.

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    AppMessageRecordFfi, MessageUpdateFfi, ReceivedMessageFfi, RuntimeMessageReceivedFfi,
    SecureDeleteExpiredResultFfi,
};

use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, owned_c_string, owned_opt_c_string, owned_vec,
};
use crate::types::common::MarmotMessageTag;
use crate::types::markdown::MarmotMarkdownDocument;

/// Convert the inner-event tags into an owned `(ptr, len)` pair.
fn owned_tags(
    values: Vec<marmot_uniffi::conversions::MessageTagFfi>,
) -> (*mut MarmotMessageTag, usize) {
    owned_vec(values.into_iter().map(Into::into).collect())
}

/// One stored application message row.
#[repr(C)]
pub struct MarmotAppMessageRecord {
    pub message_id_hex: *mut c_char,
    pub direction: *mut c_char,
    pub group_id_hex: *mut c_char,
    pub sender: *mut c_char,
    pub plaintext: *mut c_char,
    /// Parsed Markdown of `plaintext` for chat-shaped kinds; empty for
    /// non-chat kinds. Owned by this record and freed with it.
    pub content_tokens: MarmotMarkdownDocument,
    /// Nostr `kind` of the inner Marmot app event (9 chat, 7 reaction, ...).
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: *mut MarmotMessageTag,
    pub tags_len: usize,
    pub recorded_at: u64,
    pub received_at: u64,
}

impl From<AppMessageRecordFfi> for MarmotAppMessageRecord {
    fn from(value: AppMessageRecordFfi) -> Self {
        let (tags, tags_len) = owned_tags(value.tags);
        Self {
            message_id_hex: owned_c_string(value.message_id_hex),
            direction: owned_c_string(value.direction),
            group_id_hex: owned_c_string(value.group_id_hex),
            sender: owned_c_string(value.sender),
            plaintext: owned_c_string(value.plaintext),
            content_tokens: value.content_tokens.into(),
            kind: value.kind,
            tags,
            tags_len,
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
}

impl CFree for MarmotAppMessageRecord {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.message_id_hex);
            free_c_string(self.direction);
            free_c_string(self.group_id_hex);
            free_c_string(self.sender);
            free_c_string(self.plaintext);
            self.content_tokens.free_in_place();
            free_vec(self.tags, self.tags_len);
        }
    }
}

/// Free a single message record root (e.g. a subscription snapshot row).
/// NULL is a no-op.
///
/// # Safety
/// `record` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_message_record_free(record: *mut MarmotAppMessageRecord) {
    unsafe { free_boxed(record) };
}

/// Owned list of message records (`marmot_messages`).
#[repr(C)]
pub struct MarmotAppMessageRecordList {
    pub items: *mut MarmotAppMessageRecord,
    pub len: usize,
}

impl From<Vec<AppMessageRecordFfi>> for MarmotAppMessageRecordList {
    fn from(value: Vec<AppMessageRecordFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAppMessageRecordList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_messages`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_message_record_list_free(
    list: *mut MarmotAppMessageRecordList,
) {
    unsafe { free_boxed(list) };
}

/// Result of pruning expired disappearing messages: the number of rows
/// removed and the ciphertext hashes of media blobs that became orphaned.
#[repr(C)]
pub struct MarmotSecureDeleteExpiredResult {
    pub pruned_messages: u64,
    /// SHA-256 hex digests of media ciphertexts no longer referenced by any
    /// surviving message.
    pub media_ciphertext_sha256: *mut *mut c_char,
    pub media_ciphertext_sha256_len: usize,
}

impl From<SecureDeleteExpiredResultFfi> for MarmotSecureDeleteExpiredResult {
    fn from(value: SecureDeleteExpiredResultFfi) -> Self {
        let (media_ciphertext_sha256, media_ciphertext_sha256_len) = owned_vec(
            value
                .media_ciphertext_sha256
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            pruned_messages: value.pruned_messages,
            media_ciphertext_sha256,
            media_ciphertext_sha256_len,
        }
    }
}

impl CFree for MarmotSecureDeleteExpiredResult {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(
                self.media_ciphertext_sha256,
                self.media_ciphertext_sha256_len,
            );
        }
    }
}

/// Free a secure-delete result root. NULL is a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_secure_delete_expired_result_free(
    result: *mut MarmotSecureDeleteExpiredResult,
) {
    unsafe { free_boxed(result) };
}

/// One freshly delivered MLS application message.
#[repr(C)]
pub struct MarmotReceivedMessage {
    pub message_id_hex: *mut c_char,
    pub group_id_hex: *mut c_char,
    pub sender: *mut c_char,
    /// Sender's display name, when known. Nullable.
    pub sender_display_name: *mut c_char,
    pub plaintext: *mut c_char,
    /// Parsed Markdown of `plaintext` for chat-shaped kinds; empty for
    /// non-chat kinds. Owned by this record and freed with it.
    pub content_tokens: MarmotMarkdownDocument,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: *mut MarmotMessageTag,
    pub tags_len: usize,
    /// Source-event timestamp (seconds since epoch) for the MLS-delivered
    /// message. Clients should sort the timeline by this value so chronology
    /// reflects send time, not delivery time. Zero means the timestamp was
    /// unavailable at decode time.
    pub recorded_at: u64,
}

impl From<ReceivedMessageFfi> for MarmotReceivedMessage {
    fn from(value: ReceivedMessageFfi) -> Self {
        let (tags, tags_len) = owned_tags(value.tags);
        Self {
            message_id_hex: owned_c_string(value.message_id_hex),
            group_id_hex: owned_c_string(value.group_id_hex),
            sender: owned_c_string(value.sender),
            sender_display_name: owned_opt_c_string(value.sender_display_name),
            plaintext: owned_c_string(value.plaintext),
            content_tokens: value.content_tokens.into(),
            kind: value.kind,
            tags,
            tags_len,
            recorded_at: value.recorded_at,
        }
    }
}

impl CFree for MarmotReceivedMessage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.message_id_hex);
            free_c_string(self.group_id_hex);
            free_c_string(self.sender);
            free_c_string(self.sender_display_name);
            free_c_string(self.plaintext);
            self.content_tokens.free_in_place();
            free_vec(self.tags, self.tags_len);
        }
    }
}

/// A received message together with the account it was delivered to.
#[repr(C)]
pub struct MarmotRuntimeMessageReceived {
    pub account_id_hex: *mut c_char,
    pub account_label: *mut c_char,
    pub message: MarmotReceivedMessage,
}

impl From<RuntimeMessageReceivedFfi> for MarmotRuntimeMessageReceived {
    fn from(value: RuntimeMessageReceivedFfi) -> Self {
        Self {
            account_id_hex: owned_c_string(value.account_id_hex),
            account_label: owned_c_string(value.account_label),
            message: value.message.into(),
        }
    }
}

impl CFree for MarmotRuntimeMessageReceived {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_id_hex);
            free_c_string(self.account_label);
            self.message.free_in_place();
        }
    }
}

/// Free a runtime-message-received root. Never call on values embedded by
/// value inside another struct. NULL is a no-op.
///
/// # Safety
/// `received` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_runtime_message_received_free(
    received: *mut MarmotRuntimeMessageReceived,
) {
    unsafe { free_boxed(received) };
}

/// A unified update from a messages subscription. Each variant carries enough
/// context for host apps to update an in-memory timeline without holding
/// onto the underlying runtime types.
#[repr(C)]
pub enum MarmotMessageUpdate {
    /// A raw message update: chat, reply, media, reaction, delete, or the
    /// kind-9 stream-final. Materialized timeline pages also include
    /// kind-1200 stream starts as timeline record rows.
    Message {
        received: MarmotRuntimeMessageReceived,
    },
    /// A kind-1200 agent text stream start — the signal to open the QUIC
    /// preview for raw message subscribers. Its stream id, route, and brokers
    /// live on `received.message.tags`.
    AgentStreamStarted {
        received: MarmotRuntimeMessageReceived,
    },
}

impl From<MessageUpdateFfi> for MarmotMessageUpdate {
    fn from(value: MessageUpdateFfi) -> Self {
        match value {
            MessageUpdateFfi::Message { received } => Self::Message {
                received: received.into(),
            },
            MessageUpdateFfi::AgentStreamStarted { received } => Self::AgentStreamStarted {
                received: received.into(),
            },
        }
    }
}

impl CFree for MarmotMessageUpdate {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Message { received } | Self::AgentStreamStarted { received } => unsafe {
                received.free_in_place();
            },
        }
    }
}

/// Free a message-subscription update root. NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_message_update_free(update: *mut MarmotMessageUpdate) {
    unsafe { free_boxed(update) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;
    use marmot_uniffi::conversions::MessageTagFfi;
    use marmot_uniffi::{MarkdownBlockFfi, MarkdownDocumentFfi, MarkdownInlineFfi};

    fn c_str_eq(ptr: *mut c_char, expected: &str) -> bool {
        assert!(!ptr.is_null());
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid UTF-8")
            == expected
    }

    fn sample_tokens(text: &str) -> MarkdownDocumentFfi {
        MarkdownDocumentFfi {
            blocks: vec![MarkdownBlockFfi::Paragraph {
                inlines: vec![MarkdownInlineFfi::Text {
                    content: text.into(),
                }],
            }],
            truncated: false,
        }
    }

    fn sample_tags() -> Vec<MessageTagFfi> {
        vec![
            MessageTagFfi {
                values: vec!["e".to_string(), "abcd1234".to_string()],
            },
            MessageTagFfi {
                values: vec!["q".to_string(), "parent".to_string()],
            },
        ]
    }

    fn sample_record() -> AppMessageRecordFfi {
        AppMessageRecordFfi {
            message_id_hex: "msg-1".to_string(),
            direction: "outbound".to_string(),
            group_id_hex: "aabb".to_string(),
            sender: "alice".to_string(),
            plaintext: "hello burrow".to_string(),
            content_tokens: sample_tokens("hello burrow"),
            kind: 9,
            tags: sample_tags(),
            recorded_at: 1_700_000_000,
            received_at: 1_700_000_005,
        }
    }

    fn sample_received() -> ReceivedMessageFfi {
        ReceivedMessageFfi {
            message_id_hex: "msg-2".to_string(),
            group_id_hex: "ccdd".to_string(),
            sender: "bob".to_string(),
            sender_display_name: Some("Bob".to_string()),
            plaintext: "fresh dirt".to_string(),
            content_tokens: sample_tokens("fresh dirt"),
            kind: 9,
            tags: sample_tags(),
            recorded_at: 1_700_000_010,
        }
    }

    fn sample_runtime_received() -> RuntimeMessageReceivedFfi {
        RuntimeMessageReceivedFfi {
            account_id_hex: "eeff".to_string(),
            account_label: "primary".to_string(),
            message: sample_received(),
        }
    }

    #[test]
    fn app_message_record_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAppMessageRecord = sample_record().into();
        assert!(c_str_eq(mirror.message_id_hex, "msg-1"));
        assert!(c_str_eq(mirror.direction, "outbound"));
        assert!(c_str_eq(mirror.group_id_hex, "aabb"));
        assert!(c_str_eq(mirror.sender, "alice"));
        assert!(c_str_eq(mirror.plaintext, "hello burrow"));
        assert_eq!(mirror.content_tokens.blocks_len, 1);
        assert!(!mirror.content_tokens.blocks.is_null());
        assert_eq!(mirror.kind, 9);
        assert_eq!(mirror.tags_len, 2);
        let tags = unsafe { std::slice::from_raw_parts(mirror.tags, mirror.tags_len) };
        assert_eq!(tags[0].values_len, 2);
        assert!(c_str_eq(unsafe { *tags[0].values }, "e"));
        assert_eq!(mirror.recorded_at, 1_700_000_000);
        assert_eq!(mirror.received_at, 1_700_000_005);
        let root = boxed(mirror);
        unsafe { marmot_app_message_record_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn app_message_record_list_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotAppMessageRecordList = vec![sample_record(), sample_record()].into();
        assert_eq!(list.len, 2);
        assert!(!list.items.is_null());
        let items = unsafe { std::slice::from_raw_parts(list.items, list.len) };
        assert!(c_str_eq(items[1].message_id_hex, "msg-1"));
        let root = boxed(list);
        unsafe { marmot_app_message_record_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn secure_delete_expired_result_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotSecureDeleteExpiredResult = SecureDeleteExpiredResultFfi {
            pruned_messages: 4,
            media_ciphertext_sha256: vec!["aa11".to_string(), "bb22".to_string()],
        }
        .into();
        assert_eq!(mirror.pruned_messages, 4);
        assert_eq!(mirror.media_ciphertext_sha256_len, 2);
        assert!(!mirror.media_ciphertext_sha256.is_null());
        assert!(c_str_eq(
            unsafe { *mirror.media_ciphertext_sha256.add(1) },
            "bb22"
        ));
        let root = boxed(mirror);
        unsafe { marmot_secure_delete_expired_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn runtime_message_received_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotRuntimeMessageReceived = sample_runtime_received().into();
        assert!(c_str_eq(mirror.account_id_hex, "eeff"));
        assert!(c_str_eq(mirror.account_label, "primary"));
        assert!(c_str_eq(mirror.message.message_id_hex, "msg-2"));
        assert!(c_str_eq(mirror.message.sender_display_name, "Bob"));
        assert_eq!(mirror.message.content_tokens.blocks_len, 1);
        assert_eq!(mirror.message.tags_len, 2);
        assert_eq!(mirror.message.recorded_at, 1_700_000_010);
        let root = boxed(mirror);
        unsafe { marmot_runtime_message_received_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn message_update_roundtrips_both_variants() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let message: MarmotMessageUpdate = MessageUpdateFfi::Message {
            received: sample_runtime_received(),
        }
        .into();
        let MarmotMessageUpdate::Message { received } = &message else {
            panic!("expected message variant");
        };
        assert!(c_str_eq(received.account_id_hex, "eeff"));
        assert!(c_str_eq(received.message.plaintext, "fresh dirt"));
        let root = boxed(message);
        unsafe { marmot_message_update_free(root) };

        let stream: MarmotMessageUpdate = MessageUpdateFfi::AgentStreamStarted {
            received: sample_runtime_received(),
        }
        .into();
        let MarmotMessageUpdate::AgentStreamStarted { received } = &stream else {
            panic!("expected agent-stream-started variant");
        };
        assert!(c_str_eq(received.account_label, "primary"));
        assert_eq!(received.message.tags_len, 2);
        let root = boxed(stream);
        unsafe { marmot_message_update_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_vecs_and_none_fields_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let list: MarmotAppMessageRecordList = Vec::<AppMessageRecordFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_app_message_record_list_free(root) };

        let result: MarmotSecureDeleteExpiredResult = SecureDeleteExpiredResultFfi {
            pruned_messages: 0,
            media_ciphertext_sha256: Vec::new(),
        }
        .into();
        assert!(result.media_ciphertext_sha256.is_null());
        assert_eq!(result.media_ciphertext_sha256_len, 0);
        let root = boxed(result);
        unsafe { marmot_secure_delete_expired_result_free(root) };

        let mut received: MarmotReceivedMessage = ReceivedMessageFfi {
            message_id_hex: "msg-3".to_string(),
            group_id_hex: "0011".to_string(),
            sender: "carol".to_string(),
            sender_display_name: None,
            plaintext: String::new(),
            content_tokens: MarkdownDocumentFfi {
                blocks: Vec::new(),
                truncated: false,
            },
            kind: 7,
            tags: Vec::new(),
            recorded_at: 0,
        }
        .into();
        assert!(received.sender_display_name.is_null());
        assert!(received.content_tokens.blocks.is_null());
        assert_eq!(received.content_tokens.blocks_len, 0);
        assert!(received.tags.is_null());
        assert_eq!(received.tags_len, 0);
        unsafe { received.free_in_place() };
    }
}
