//! C mirrors of linking a new device of this account, as each device's
//! screen shows it.

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    DeviceLinkEmojiFfi, DeviceLinkEndReasonFfi, DeviceLinkPromptFfi, DeviceLinkPromptStateFfi,
    DeviceLinkSnapshotFfi, NewDeviceLinkStateFfi,
};

use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_c_string, free_vec, owned_c_string, owned_vec};

c_enum! {
    /// Why a link ended without one device adding the other.
    MarmotDeviceLinkEndReason from DeviceLinkEndReasonFfi {
        /// This device's user cancelled.
        Cancelled,
        /// The other device cancelled, or its user chose Not now.
        CancelledElsewhere,
        /// A user said the codes differ.
        CodesDiffer,
        /// The exchange failed a check, so the code can't be trusted.
        VerificationFailed,
        /// Time ran out.
        TimedOut,
        /// Another device of this account is linking the sign-in.
        AnsweredElsewhere,
        /// The sign-in's client can't join the device group.
        CannotLink,
        /// The sign-in was rejected on one of this account's devices.
        Rejected,
        /// Both users confirmed, but adding the device failed, or its Welcome
        /// did not reach the relays before the new device stopped waiting.
        LinkFailed,
    }
}

c_mirror! {
    /// One emoji of the code. `description` is its English description, for
    /// screen readers; users compare the pictures.
    MarmotDeviceLinkEmoji from DeviceLinkEmojiFfi {
        str emoji,
        str description,
    }
}

fn owned_code(code: Vec<DeviceLinkEmojiFfi>) -> (*mut MarmotDeviceLinkEmoji, usize) {
    owned_vec(code.into_iter().map(Into::into).collect())
}

/// The new device's side of a link, as its screen shows it. `code` holds
/// the seven emoji both screens show.
#[repr(C)]
pub enum MarmotNewDeviceLinkState {
    /// Waiting for a device already signed in to answer.
    WaitingForAnswer,
    /// Offer "They match" and cancel.
    Comparing {
        code: *mut MarmotDeviceLinkEmoji,
        code_len: usize,
    },
    /// This user confirmed; the other device's user has not yet.
    WaitingForOtherDevice,
    /// Both users confirmed. Waiting for the other device to add this one.
    Joining,
    /// This device joined the account's device group.
    Linked,
    Ended {
        reason: MarmotDeviceLinkEndReason,
    },
}

impl From<NewDeviceLinkStateFfi> for MarmotNewDeviceLinkState {
    fn from(value: NewDeviceLinkStateFfi) -> Self {
        match value {
            NewDeviceLinkStateFfi::WaitingForAnswer => Self::WaitingForAnswer,
            NewDeviceLinkStateFfi::Comparing { code } => {
                let (code, code_len) = owned_code(code);
                Self::Comparing { code, code_len }
            }
            NewDeviceLinkStateFfi::WaitingForOtherDevice => Self::WaitingForOtherDevice,
            NewDeviceLinkStateFfi::Joining => Self::Joining,
            NewDeviceLinkStateFfi::Linked => Self::Linked,
            NewDeviceLinkStateFfi::Ended { reason } => Self::Ended {
                reason: reason.into(),
            },
        }
    }
}

impl CFree for MarmotNewDeviceLinkState {
    unsafe fn free_in_place(&mut self) {
        if let Self::Comparing { code, code_len } = self {
            unsafe { free_vec(*code, *code_len) };
        }
    }
}

/// Where a prompt on a device already signed in stands.
#[repr(C)]
pub enum MarmotDeviceLinkPromptState {
    /// Checking the sign-in's KeyPackage, or waiting for the code.
    Preparing,
    /// Both screens show `code`. Offer Link device and Not now.
    Comparing {
        code: *mut MarmotDeviceLinkEmoji,
        code_len: usize,
    },
    /// More than one sign-in asked to link at once, so Link is offered for
    /// none of them.
    CompetingRequests,
    /// This device answered too many link requests lately. It tries again at
    /// `retry_at`, in Unix seconds.
    RateLimited {
        retry_at: u64,
    },
    /// The sign-in's client can't join the device group. `missing` names
    /// what it lacks.
    CannotLink {
        missing: *mut *mut c_char,
        missing_len: usize,
    },
    /// The account has 20 linked devices. Remove one first.
    TooManyDevices,
    /// This user chose Link device. Waiting for the new device's
    /// confirmation, then for relays to confirm the change that adds it and
    /// take its Welcome.
    Linking,
    /// This device added it: relays confirmed the change and took its
    /// Welcome.
    Linked,
    /// Another device added it: "<device_label> was added by
    /// <added_by_label>". A label the roster lacks is empty.
    AddedElsewhere {
        device_label: *mut c_char,
        added_by_label: *mut c_char,
    },
    Ended {
        reason: MarmotDeviceLinkEndReason,
    },
}

impl From<DeviceLinkPromptStateFfi> for MarmotDeviceLinkPromptState {
    fn from(value: DeviceLinkPromptStateFfi) -> Self {
        match value {
            DeviceLinkPromptStateFfi::Preparing => Self::Preparing,
            DeviceLinkPromptStateFfi::Comparing { code } => {
                let (code, code_len) = owned_code(code);
                Self::Comparing { code, code_len }
            }
            DeviceLinkPromptStateFfi::CompetingRequests => Self::CompetingRequests,
            DeviceLinkPromptStateFfi::RateLimited { retry_at } => Self::RateLimited { retry_at },
            DeviceLinkPromptStateFfi::CannotLink { missing } => {
                let (missing, missing_len) =
                    owned_vec(missing.into_iter().map(owned_c_string).collect());
                Self::CannotLink {
                    missing,
                    missing_len,
                }
            }
            DeviceLinkPromptStateFfi::TooManyDevices => Self::TooManyDevices,
            DeviceLinkPromptStateFfi::Linking => Self::Linking,
            DeviceLinkPromptStateFfi::Linked => Self::Linked,
            DeviceLinkPromptStateFfi::AddedElsewhere {
                device_label,
                added_by_label,
            } => Self::AddedElsewhere {
                device_label: owned_c_string(device_label),
                added_by_label: owned_c_string(added_by_label),
            },
            DeviceLinkPromptStateFfi::Ended { reason } => Self::Ended {
                reason: reason.into(),
            },
        }
    }
}

impl CFree for MarmotDeviceLinkPromptState {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Comparing { code, code_len } => unsafe { free_vec(*code, *code_len) },
            Self::CannotLink {
                missing,
                missing_len,
            } => unsafe { free_vec(*missing, *missing_len) },
            Self::AddedElsewhere {
                device_label,
                added_by_label,
            } => unsafe {
                free_c_string(*device_label);
                free_c_string(*added_by_label);
            },
            _ => {}
        }
    }
}

c_mirror! {
    /// A new sign-in this device can link. `prompt_id` is the opaque local
    /// id `marmot_link_device` and `marmot_decline_device_link` take.
    /// `slot_id_hex` (64 lowercase hex characters) is NULL until the
    /// sign-in's KeyPackage was found. `requested_at` is in Unix seconds.
    MarmotDeviceLinkPrompt from DeviceLinkPromptFfi {
        str prompt_id,
        opt_str slot_id_hex,
        copy requested_at: u64,
        rec state: MarmotDeviceLinkPromptState,
    }
}

c_mirror! {
    /// Linking as this device shows it. `new_device` is NULL unless this
    /// device asked to be linked; `prompts` lists the sign-ins it can link.
    MarmotDeviceLinkSnapshot from DeviceLinkSnapshotFfi,
    free marmot_device_link_snapshot_free {
        opt_rec new_device: MarmotNewDeviceLinkState,
        vec prompts/prompts_len: MarmotDeviceLinkPrompt,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    use marmot_uniffi::conversions::DeviceLinkEndReasonFfi as Reason;

    fn code() -> Vec<DeviceLinkEmojiFfi> {
        (0..7)
            .map(|index| DeviceLinkEmojiFfi {
                emoji: "🐶".to_owned(),
                description: format!("Dog {index}"),
            })
            .collect()
    }

    fn prompt(state: DeviceLinkPromptStateFfi) -> DeviceLinkPromptFfi {
        DeviceLinkPromptFfi {
            prompt_id: "prompt".to_owned(),
            slot_id_hex: Some("ab".repeat(32)),
            requested_at: 7,
            state,
        }
    }

    #[test]
    fn device_link_snapshot_deep_free_covers_every_state() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let new_device_states = [
            NewDeviceLinkStateFfi::WaitingForAnswer,
            NewDeviceLinkStateFfi::Comparing { code: code() },
            NewDeviceLinkStateFfi::WaitingForOtherDevice,
            NewDeviceLinkStateFfi::Joining,
            NewDeviceLinkStateFfi::Linked,
            NewDeviceLinkStateFfi::Ended {
                reason: Reason::LinkFailed,
            },
        ];
        for new_device in new_device_states {
            let snapshot = boxed(MarmotDeviceLinkSnapshot::from(DeviceLinkSnapshotFfi {
                new_device: Some(new_device),
                prompts: Vec::new(),
            }));
            unsafe {
                assert!(!(*snapshot).new_device.is_null());
                assert_eq!((*snapshot).prompts_len, 0);
                marmot_device_link_snapshot_free(snapshot);
            }
        }
        let snapshot = boxed(MarmotDeviceLinkSnapshot::from(DeviceLinkSnapshotFfi {
            new_device: None,
            prompts: vec![
                prompt(DeviceLinkPromptStateFfi::Preparing),
                prompt(DeviceLinkPromptStateFfi::Comparing { code: code() }),
                prompt(DeviceLinkPromptStateFfi::CompetingRequests),
                prompt(DeviceLinkPromptStateFfi::RateLimited { retry_at: 9 }),
                prompt(DeviceLinkPromptStateFfi::CannotLink {
                    missing: vec!["0x800d".to_owned(), "0xf2ee".to_owned()],
                }),
                prompt(DeviceLinkPromptStateFfi::TooManyDevices),
                prompt(DeviceLinkPromptStateFfi::Linking),
                prompt(DeviceLinkPromptStateFfi::Linked),
                prompt(DeviceLinkPromptStateFfi::AddedElsewhere {
                    device_label: "Tablet".to_owned(),
                    added_by_label: String::new(),
                }),
                prompt(DeviceLinkPromptStateFfi::Ended {
                    reason: Reason::CodesDiffer,
                }),
            ],
        }));
        unsafe {
            assert!((*snapshot).new_device.is_null());
            assert_eq!((*snapshot).prompts_len, 10);
            let comparing = &*(*snapshot).prompts.add(1);
            let MarmotDeviceLinkPromptState::Comparing { code, code_len } = &comparing.state else {
                panic!("unexpected prompt state");
            };
            assert_eq!(*code_len, 7);
            assert_eq!(
                std::ffi::CStr::from_ptr((*code.add(6)).description)
                    .to_str()
                    .unwrap(),
                "Dog 6"
            );
            let cannot_link = &*(*snapshot).prompts.add(4);
            let MarmotDeviceLinkPromptState::CannotLink {
                missing,
                missing_len,
            } = &cannot_link.state
            else {
                panic!("unexpected prompt state");
            };
            assert_eq!(*missing_len, 2);
            assert_eq!(
                std::ffi::CStr::from_ptr(*missing.add(1)).to_str().unwrap(),
                "0xf2ee"
            );
            let added = &*(*snapshot).prompts.add(8);
            let MarmotDeviceLinkPromptState::AddedElsewhere {
                device_label,
                added_by_label,
            } = &added.state
            else {
                panic!("unexpected prompt state");
            };
            assert_eq!(
                std::ffi::CStr::from_ptr(*device_label).to_str().unwrap(),
                "Tablet"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(*added_by_label).to_str().unwrap(),
                ""
            );
            marmot_device_link_snapshot_free(snapshot);
            marmot_device_link_snapshot_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
