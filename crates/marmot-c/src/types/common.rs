//! Shared cross-domain mirrors.

use marmot_uniffi::conversions::MessageTagFfi;

use crate::macros::c_mirror;

/// Owned list of strings (relay lists, admin ids, …). Free with
/// `marmot_string_list_free`.
#[repr(C)]
pub struct MarmotStringList {
    pub items: *mut *mut ::std::ffi::c_char,
    pub len: usize,
}

impl From<Vec<String>> for MarmotStringList {
    fn from(value: Vec<String>) -> Self {
        let (items, len) = crate::memory::owned_vec(
            value
                .into_iter()
                .map(crate::memory::owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self { items, len }
    }
}

impl crate::memory::CFree for MarmotStringList {
    unsafe fn free_in_place(&mut self) {
        unsafe { crate::memory::free_vec(self.items, self.len) };
    }
}

/// Free a string list returned by this library. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_string_list_free(list: *mut MarmotStringList) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(list) });
}

c_mirror! {
    /// One Nostr tag of the inner Marmot app event, as its string values.
    MarmotMessageTag from MessageTagFfi,
    free marmot_message_tag_free {
        str_vec values/values_len,
    }
}
