//! C mirrors of this account's own devices, from its device group's roster.

use marmot_uniffi::conversions::{LinkedDeviceFfi, LinkedDeviceStatusFfi};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// A linked device's status in the roster.
    MarmotLinkedDeviceStatus from LinkedDeviceStatusFfi {
        Active,
        /// Its siblings marked it inactive.
        Inactive,
        /// It recorded that it is signing out.
        Leaving,
    }
}

c_mirror! {
    /// One of this account's own devices, as the roster of the device group
    /// this device trusts lists it. `slot_id_hex` (64 lowercase hex
    /// characters) is the handle actions on the device take. `label`,
    /// `client` and `platform` are empty until set. `linked_at` is in Unix
    /// seconds. `linked_by_slot_id_hex` is NULL for the founder.
    /// `last_active_at` (Unix seconds, valid when `has_last_active_at`) is
    /// when a heartbeat last showed the device running; never set for this
    /// device. `inactive` is this device's own judgement, 30 days after the
    /// later of that and when it first found the device in the roster; the
    /// roster's mark is `status` `Inactive`.
    MarmotLinkedDevice from LinkedDeviceFfi,
    list(MarmotLinkedDeviceList, marmot_linked_device_list_free) {
        str slot_id_hex,
        copy is_this_device: bool,
        str label,
        str client,
        str platform,
        copy linked_at: u64,
        opt_str linked_by_slot_id_hex,
        copy status: MarmotLinkedDeviceStatus,
        copy add_to_all_chats: bool,
        copy bring_history: bool,
        copy keep_while_inactive: bool,
        opt_copy has_last_active_at/last_active_at: u64,
        copy inactive: bool,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn linked_device_list_deep_free_preserves_every_field() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let list = boxed(MarmotLinkedDeviceList::from(vec![
            LinkedDeviceFfi {
                slot_id_hex: "ab".repeat(32),
                is_this_device: true,
                label: "Phone".to_owned(),
                client: "White Noise".to_owned(),
                platform: "Android".to_owned(),
                linked_at: 7,
                linked_by_slot_id_hex: None,
                status: LinkedDeviceStatusFfi::Active,
                add_to_all_chats: false,
                bring_history: false,
                keep_while_inactive: false,
                last_active_at: None,
                inactive: false,
            },
            LinkedDeviceFfi {
                slot_id_hex: "cd".repeat(32),
                is_this_device: false,
                label: String::new(),
                client: String::new(),
                platform: String::new(),
                linked_at: 9,
                linked_by_slot_id_hex: Some("ab".repeat(32)),
                status: LinkedDeviceStatusFfi::Leaving,
                add_to_all_chats: true,
                bring_history: false,
                keep_while_inactive: true,
                last_active_at: Some(11),
                inactive: true,
            },
        ]));
        unsafe {
            assert_eq!((*list).len, 2);
            let first = &*(*list).items;
            assert!(first.is_this_device);
            assert_eq!(first.linked_at, 7);
            assert!(first.linked_by_slot_id_hex.is_null());
            assert_eq!(first.status, MarmotLinkedDeviceStatus::Active);
            assert_eq!(
                std::ffi::CStr::from_ptr(first.label).to_str().unwrap(),
                "Phone"
            );
            let second = &*(*list).items.add(1);
            assert!(!second.is_this_device);
            assert_eq!(
                std::ffi::CStr::from_ptr(second.linked_by_slot_id_hex)
                    .to_str()
                    .unwrap(),
                "ab".repeat(32)
            );
            assert_eq!(second.status, MarmotLinkedDeviceStatus::Leaving);
            assert!(second.add_to_all_chats);
            assert!(!second.bring_history);
            assert!(second.keep_while_inactive);
            assert!(!first.has_last_active_at);
            assert!(!first.inactive);
            assert!(second.has_last_active_at);
            assert_eq!(second.last_active_at, 11);
            assert!(second.inactive);
            marmot_linked_device_list_free(list);
            marmot_linked_device_list_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
