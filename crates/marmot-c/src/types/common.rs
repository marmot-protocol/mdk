//! C mirrors of the shared conversions (`marmot-uniffi/src/conversions/common.rs`),
//! plus the shared string-list root used by commands returning `Vec<String>`
//! (e.g. `marmot_account_nip65_relays`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{MessageTagFfi, SelfMembershipFfi};

use crate::memory::{CFree, free_boxed, free_vec, owned_c_string, owned_vec};

/// The local account's own membership in a group: an active `Member`, or a
/// terminal state describing how it left — `Left` (a voluntary self-removal
/// or declined invite) or `Removed` (evicted by another member). Surfaced on
/// both the chat-list row and the group-detail record.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotSelfMembership {
    Member,
    Left,
    Removed,
}

impl From<SelfMembershipFfi> for MarmotSelfMembership {
    fn from(value: SelfMembershipFfi) -> Self {
        match value {
            SelfMembershipFfi::Member => MarmotSelfMembership::Member,
            SelfMembershipFfi::Left => MarmotSelfMembership::Left,
            SelfMembershipFfi::Removed => MarmotSelfMembership::Removed,
        }
    }
}

impl CFree for MarmotSelfMembership {
    unsafe fn free_in_place(&mut self) {}
}

/// One Nostr tag from an inner Marmot app event, e.g. `["e", "<id>"]` or an
/// `["imeta", …]` media descriptor. Host apps branch on the inner event
/// `kind` plus these tags instead of a fixed payload enum.
#[repr(C)]
pub struct MarmotMessageTag {
    pub values: *mut *mut c_char,
    pub values_len: usize,
}

impl From<MessageTagFfi> for MarmotMessageTag {
    fn from(value: MessageTagFfi) -> Self {
        let (values, values_len) = owned_vec(
            value
                .values
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self { values, values_len }
    }
}

impl CFree for MarmotMessageTag {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.values, self.values_len) };
    }
}

/// Free a single message tag root. NULL is a no-op. Tags nested inside a
/// message record are owned by that record and freed with it — never
/// individually.
///
/// # Safety
/// `tag` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_message_tag_free(tag: *mut MarmotMessageTag) {
    unsafe { free_boxed(tag) };
}

/// Owned list of plain strings. Shared root for every command that returns
/// a list of strings (e.g. `marmot_account_nip65_relays`).
#[repr(C)]
pub struct MarmotStringList {
    pub items: *mut *mut c_char,
    pub len: usize,
}

impl From<Vec<String>> for MarmotStringList {
    fn from(value: Vec<String>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(owned_c_string).collect::<Vec<_>>());
        Self { items, len }
    }
}

impl CFree for MarmotStringList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a string list returned by this library. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_string_list_free(list: *mut MarmotStringList) {
    unsafe { free_boxed(list) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    #[test]
    fn message_tag_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotMessageTag = MessageTagFfi {
            values: vec!["e".to_string(), "abcd1234".to_string()],
        }
        .into();
        assert_eq!(mirror.values_len, 2);
        assert!(!mirror.values.is_null());
        let first = unsafe { std::ffi::CStr::from_ptr(*mirror.values) }
            .to_str()
            .expect("valid UTF-8");
        assert_eq!(first, "e");
        let root = boxed(mirror);
        unsafe { marmot_message_tag_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn string_list_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotStringList = vec![
            "wss://relay.example/one".to_string(),
            "wss://relay.example/two".to_string(),
        ]
        .into();
        assert_eq!(list.len, 2);
        assert!(!list.items.is_null());
        let second = unsafe { std::ffi::CStr::from_ptr(*list.items.add(1)) }
            .to_str()
            .expect("valid UTF-8");
        assert_eq!(second, "wss://relay.example/two");
        let root = boxed(list);
        unsafe { marmot_string_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn self_membership_maps_all_variants() {
        let _guard = crate::memory::audit::test_lock();
        assert_eq!(
            MarmotSelfMembership::from(SelfMembershipFfi::Member),
            MarmotSelfMembership::Member
        );
        assert_eq!(
            MarmotSelfMembership::from(SelfMembershipFfi::Left),
            MarmotSelfMembership::Left
        );
        assert_eq!(
            MarmotSelfMembership::from(SelfMembershipFfi::Removed),
            MarmotSelfMembership::Removed
        );
    }

    #[test]
    fn empty_lists_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let list: MarmotStringList = Vec::<String>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_string_list_free(root) };

        let tag: MarmotMessageTag = MessageTagFfi { values: Vec::new() }.into();
        assert!(tag.values.is_null());
        assert_eq!(tag.values_len, 0);
        let root = boxed(tag);
        unsafe { marmot_message_tag_free(root) };
    }
}
