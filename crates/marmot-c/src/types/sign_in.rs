//! C mirrors of the sign-ins of this account that this device does not
//! recognize.

use marmot_uniffi::conversions::{
    SignInResponseFfi, UnrecognizedSignInFfi, UnrecognizedSignInStateFfi,
};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Where an unrecognized sign-in stands on this device.
    MarmotUnrecognizedSignInState from UnrecognizedSignInStateFfi {
        /// Waiting for an answer.
        Prompt,
        /// Answered Not now: listed with no prompt.
        NotNow,
        /// Another device linked it while its prompt here waited.
        LinkedElsewhere,
        /// Another device rejected it while its prompt here waited.
        RejectedElsewhere,
    }
}

c_enum! {
    /// An answer to an unrecognized sign-in, passed to
    /// `marmot_answer_sign_in` as a `uint32_t`.
    MarmotSignInResponse from SignInResponseFfi {
        /// Keep it listed, with no prompt.
        NotNow,
        /// It was not the user: record it as rejected in the device group's
        /// roster.
        Reject,
        /// End a prompt another device already answered.
        Dismiss,
    }
}

impl MarmotSignInResponse {
    pub(crate) fn to_ffi(self) -> SignInResponseFfi {
        match self {
            Self::NotNow => SignInResponseFfi::NotNow,
            Self::Reject => SignInResponseFfi::Reject,
            Self::Dismiss => SignInResponseFfi::Dismiss,
        }
    }
}

c_mirror! {
    /// A sign-in of this account that this device does not recognize.
    /// `slot_id_hex` is the handle answers take. `client` is empty when the
    /// sign-in reports none. `appeared_at` and `last_seen_at` are in Unix
    /// seconds. `before_this_device` means it was signed in before this
    /// device: ask whether the user still has it, not whether it was them.
    /// `linked_by_slot_id_hex` is set only for `LinkedElsewhere`, and may be
    /// NULL there too.
    MarmotUnrecognizedSignIn from UnrecognizedSignInFfi,
    list(MarmotUnrecognizedSignInList, marmot_unrecognized_sign_in_list_free) {
        str slot_id_hex,
        str client,
        copy appeared_at: u64,
        copy last_seen_at: u64,
        copy before_this_device: bool,
        copy signed_in: bool,
        copy state: MarmotUnrecognizedSignInState,
        opt_str linked_by_slot_id_hex,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn unrecognized_sign_in_list_deep_free_preserves_every_field() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let list = boxed(MarmotUnrecognizedSignInList::from(vec![
            UnrecognizedSignInFfi {
                slot_id_hex: "ab".repeat(32),
                client: "White Noise".to_owned(),
                appeared_at: 7,
                last_seen_at: 9,
                before_this_device: true,
                signed_in: true,
                state: UnrecognizedSignInStateFfi::Prompt,
                linked_by_slot_id_hex: None,
            },
            UnrecognizedSignInFfi {
                slot_id_hex: "cd".repeat(32),
                client: String::new(),
                appeared_at: 11,
                last_seen_at: 13,
                before_this_device: false,
                signed_in: false,
                state: UnrecognizedSignInStateFfi::LinkedElsewhere,
                linked_by_slot_id_hex: Some("ef".repeat(32)),
            },
        ]));
        unsafe {
            assert_eq!((*list).len, 2);
            let first = &*(*list).items;
            assert_eq!(
                std::ffi::CStr::from_ptr(first.client).to_str().unwrap(),
                "White Noise"
            );
            assert_eq!((first.appeared_at, first.last_seen_at), (7, 9));
            assert!(first.before_this_device && first.signed_in);
            assert_eq!(first.state, MarmotUnrecognizedSignInState::Prompt);
            assert!(first.linked_by_slot_id_hex.is_null());
            let second = &*(*list).items.add(1);
            assert!(!second.before_this_device && !second.signed_in);
            assert_eq!(second.state, MarmotUnrecognizedSignInState::LinkedElsewhere);
            assert_eq!(
                std::ffi::CStr::from_ptr(second.linked_by_slot_id_hex)
                    .to_str()
                    .unwrap(),
                "ef".repeat(32)
            );
            marmot_unrecognized_sign_in_list_free(list);
            marmot_unrecognized_sign_in_list_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }

    #[test]
    fn sign_in_responses_come_only_from_their_discriminants() {
        assert_eq!(
            MarmotSignInResponse::from_c(0).unwrap().to_ffi(),
            SignInResponseFfi::NotNow
        );
        assert_eq!(
            MarmotSignInResponse::from_c(2).unwrap().to_ffi(),
            SignInResponseFfi::Dismiss
        );
        assert!(MarmotSignInResponse::from_c(3).is_err());
    }
}
