//! C mirrors of chat history from another of this account's devices: the
//! device an imported row came from, and each held chat's history state.

use marmot_uniffi::conversions::{
    ChatHistoryImportFfi, ChatHistoryImportStateFfi, HistoryImportSourceFfi,
};

use crate::macros::c_mirror;
use crate::memory::CFree;

c_mirror! {
    /// The device a row or a chat's history was imported from.
    /// `device_slot_id_hex` is its roster slot, as `marmot_linked_devices`
    /// names it. `device_label` is its name now: empty when it has none, is
    /// no longer linked, or this device has not read the roster since it
    /// started; show "another device" then. It follows
    /// `LinkedDevicesChanged`.
    MarmotHistoryImportSource from HistoryImportSourceFfi {
        str device_slot_id_hex,
        str device_label,
    }
}

/// Where a chat's history from another device stands.
#[repr(C)]
pub enum MarmotChatHistoryImportState {
    /// A delivery arrived and waits to be imported, as while its bundle is
    /// fetched. `retrying` once an attempt to get one of its bundles failed;
    /// it is tried again later.
    Receiving { retrying: bool },
    /// Its latest import: the device it came from, and when, in Unix
    /// seconds.
    Imported {
        from: MarmotHistoryImportSource,
        at: u64,
    },
}

impl From<ChatHistoryImportStateFfi> for MarmotChatHistoryImportState {
    fn from(value: ChatHistoryImportStateFfi) -> Self {
        match value {
            ChatHistoryImportStateFfi::Receiving { retrying } => Self::Receiving { retrying },
            ChatHistoryImportStateFfi::Imported { from, at } => Self::Imported {
                from: from.into(),
                at,
            },
        }
    }
}

impl CFree for MarmotChatHistoryImportState {
    unsafe fn free_in_place(&mut self) {
        if let Self::Imported { from, .. } = self {
            unsafe { from.free_in_place() };
        }
    }
}

c_mirror! {
    /// A held chat whose history from another device is arriving or has
    /// arrived.
    MarmotChatHistoryImport from ChatHistoryImportFfi,
    list(MarmotChatHistoryImportList, marmot_chat_history_import_list_free) {
        str group_id_hex,
        rec state: MarmotChatHistoryImportState,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn chat_history_import_list_deep_free_preserves_every_field() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let list = boxed(MarmotChatHistoryImportList::from(vec![
            ChatHistoryImportFfi {
                group_id_hex: "aa".repeat(16),
                state: ChatHistoryImportStateFfi::Receiving { retrying: true },
            },
            ChatHistoryImportFfi {
                group_id_hex: "bb".repeat(16),
                state: ChatHistoryImportStateFfi::Imported {
                    from: HistoryImportSourceFfi {
                        device_slot_id_hex: "cd".repeat(32),
                        device_label: "Phone".to_owned(),
                    },
                    at: 42,
                },
            },
        ]));
        unsafe {
            assert_eq!((*list).len, 2);
            let first = &*(*list).items;
            assert_eq!(
                std::ffi::CStr::from_ptr(first.group_id_hex)
                    .to_str()
                    .unwrap(),
                "aa".repeat(16)
            );
            assert!(matches!(
                first.state,
                MarmotChatHistoryImportState::Receiving { retrying: true }
            ));
            let second = &*(*list).items.add(1);
            let MarmotChatHistoryImportState::Imported { from, at } = &second.state else {
                panic!("an import");
            };
            assert_eq!(*at, 42);
            assert_eq!(
                std::ffi::CStr::from_ptr(from.device_slot_id_hex)
                    .to_str()
                    .unwrap(),
                "cd".repeat(32)
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(from.device_label)
                    .to_str()
                    .unwrap(),
                "Phone"
            );
            marmot_chat_history_import_list_free(list);
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
