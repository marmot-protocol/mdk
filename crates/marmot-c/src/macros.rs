//! Declarative macros that generate the entire `#[repr(C)]` mirror surface.
//!
//! Every runtime record crosses the boundary the same way: a `#[repr(C)]`
//! struct owned by C, built with `From<…Ffi>`, released by a deep-free
//! (`CFree`) behind a `marmot_*_free` entry point. Instead of hand-writing
//! that quartet per type (~40 lines each), a field-spec line per field
//! drives these macros:
//!
//! ```text
//! c_mirror! {
//!     /// One signed-in (or signed-out but known) account.
//!     MarmotAccountSummary from AccountSummaryFfi,
//!     free marmot_account_summary_free,
//!     list(MarmotAccountSummaryList, marmot_account_summary_list_free) {
//!         str label,                       // String        -> owned char*
//!         str account_id_hex,
//!         copy local_signing: bool,        // scalar/enum   -> by value
//!     }
//! }
//! ```
//!
//! Field kinds:
//! - `str f` / `opt_str f` — `String` / `Option<String>` → owned (nullable)
//!   `char *`.
//! - `copy f: T` — scalar or fieldless-enum mirror, converted with `.into()`.
//! - `enum_val f: M` — fieldless-enum mirror carried as its `uint32_t`
//!   discriminant. Used where C also *writes* the field (borrowed input
//!   structs): a caller-supplied out-of-range enum value would be an
//!   invalid Rust discriminant, so the struct holds an integer and
//!   `M::from_c` validates it on the way in.
//! - `opt_copy has_f/f: T` — `Option<scalar>` → `has_f: bool` + `f: T`
//!   (zero when unset).
//! - `rec f: M from F` — nested record by value.
//! - `opt_rec f: M from F` — `Option<record>` → nullable owned `*mut M`.
//! - `vec f/f_len: M from F` — `Vec<record>` → owned `(ptr, len)` pair.
//! - `str_vec f/f_len` — `Vec<String>` → owned `(char**, len)` pair.
//! - `bytes f/f_len` — `Vec<u8>` → owned `(u8*, len)` pair.
//!
//! cbindgen sees the expanded items (macro expansion is enabled in
//! `c-header` generation), so the C header carries the same structs, docs,
//! and free functions as hand-written code would.

/// Generate a `#[repr(C)]` mirror struct + `From<Ffi>` + `CFree` (+ free
/// entry point, + optional list wrapper) from a field spec.
macro_rules! c_mirror {
    // `free` names an exported deep-free entry point; omit it for types
    // that only ever cross the boundary embedded in another root.
    (
        $(#[$m:meta])* $name:ident from $ffi:ty
        $(, free $free:ident)?
        $(, list($list:ident, $list_free:ident))?
        { $($body:tt)* }
    ) => {
        c_mirror!(@munch [$(#[$m])*] $name, $ffi, value, this, {} {} {} {} $($body)*);

        $(
            /// Free a value of this type returned by this library. NULL
            /// is a no-op.
            ///
            /// # Safety
            /// The pointer must be NULL or an unfreed pointer returned by
            /// this library.
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $free(ptr: *mut $name) {
                crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(ptr) });
            }
        )?

        $(crate::macros::c_list!($list, $name, $ffi, free $list_free);)?
    };

    // Terminal: emit struct, From, CFree from the four accumulators.
    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
    ) => {
        $($m)*
        #[repr(C)]
        pub struct $name { $($sf)* }

        impl From<$ffi> for $name {
            fn from($value: $ffi) -> Self {
                $($lets)*
                Self { $($names)* }
            }
        }

        impl crate::memory::CFree for $name {
            // All-scalar mirrors expand to an empty free body.
            #[allow(unused_unsafe, unused_variables)]
            unsafe fn free_in_place(&mut self) {
                // Rebound so the field-spec arms can reference the value
                // hygienically across macro expansion steps.
                let $this = self;
                unsafe { $($fr)* }
            }
        }
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* str $f:ident, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut ::std::ffi::c_char,}
            {$($lets)* let $f = crate::memory::owned_c_string($value.$f);}
            {$($names)* $f,}
            {$($fr)* crate::memory::free_c_string($this.$f);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* opt_str $f:ident, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut ::std::ffi::c_char,}
            {$($lets)* let $f = crate::memory::owned_opt_c_string($value.$f);}
            {$($names)* $f,}
            {$($fr)* crate::memory::free_c_string($this.$f);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* copy $f:ident: $t:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: $t,}
            {$($lets)* let $f: $t = $value.$f.into();}
            {$($names)* $f,}
            {$($fr)*}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* enum_val $f:ident: $mir:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: u32,}
            {$($lets)* let $f = <$mir>::from($value.$f) as u32;}
            {$($names)* $f,}
            {$($fr)*}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* opt_copy $hf:ident/$f:ident: $t:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)*
                $(#[$fm])* pub $hf: bool,
                #[doc = "Only meaningful when the matching `has_` flag is set."]
                pub $f: $t,}
            {$($lets)*
                let $hf = $value.$f.is_some();
                let $f: $t = $value.$f.map(Into::into).unwrap_or_default();}
            {$($names)* $hf, $f,}
            {$($fr)*}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* rec $f:ident: $mir:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: $mir,}
            {$($lets)* let $f: $mir = $value.$f.into();}
            {$($names)* $f,}
            {$($fr)* crate::memory::CFree::free_in_place(&mut $this.$f);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* opt_rec $f:ident: $mir:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut $mir,}
            {$($lets)* let $f = crate::memory::boxed_opt($value.$f.map(<$mir>::from));}
            {$($names)* $f,}
            {$($fr)* crate::memory::free_boxed($this.$f);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* vec $f:ident/$fl:ident: $mir:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut $mir, pub $fl: usize,}
            {$($lets)* let ($f, $fl) = crate::memory::owned_vec(
                $value.$f.into_iter().map(<$mir>::from).collect());}
            {$($names)* $f, $fl,}
            {$($fr)* crate::memory::free_vec($this.$f, $this.$fl);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* str_vec $f:ident/$fl:ident, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut *mut ::std::ffi::c_char, pub $fl: usize,}
            {$($lets)* let ($f, $fl) = crate::memory::owned_vec(
                $value.$f.into_iter().map(crate::memory::owned_c_string).collect::<Vec<_>>());}
            {$($names)* $f, $fl,}
            {$($fr)* crate::memory::free_vec($this.$f, $this.$fl);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* prim_vec $f:ident/$fl:ident: $t:ty, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut $t, pub $fl: usize,}
            {$($lets)* let ($f, $fl) = crate::memory::owned_vec($value.$f);}
            {$($names)* $f, $fl,}
            {$($fr)* crate::memory::free_vec($this.$f, $this.$fl);}
            $($rest)*);
    };

    (@munch [$($m:tt)*] $name:ident, $ffi:ty, $value:ident, $this:ident,
        {$($sf:tt)*} {$($lets:tt)*} {$($names:tt)*} {$($fr:tt)*}
        $(#[$fm:meta])* bytes $f:ident/$fl:ident, $($rest:tt)*
    ) => {
        c_mirror!(@munch [$($m)*] $name, $ffi, $value, $this,
            {$($sf)* $(#[$fm])* pub $f: *mut u8, pub $fl: usize,}
            {$($lets)* let ($f, $fl) = crate::memory::owned_vec($value.$f);}
            {$($names)* $f, $fl,}
            {$($fr)* crate::memory::free_vec($this.$f, $this.$fl);}
            $($rest)*);
    };
}

/// Generate an owned `(items, len)` list wrapper over a mirror type, with
/// `From<Vec<Ffi>>`, `CFree`, and a free entry point.
macro_rules! c_list {
    ($(#[$m:meta])* $list:ident, $item:ident, $ffi:ty, free $free:ident) => {
        $(#[$m])*
        #[doc = "Owned list; free the root with its `_free` function only."]
        #[repr(C)]
        pub struct $list {
            pub items: *mut $item,
            pub len: usize,
        }

        impl From<Vec<$ffi>> for $list {
            fn from(value: Vec<$ffi>) -> Self {
                let (items, len) =
                    crate::memory::owned_vec(value.into_iter().map(<$item>::from).collect());
                Self { items, len }
            }
        }

        impl crate::memory::CFree for $list {
            unsafe fn free_in_place(&mut self) {
                unsafe { crate::memory::free_vec(self.items, self.len) };
            }
        }

        /// Free a list returned by this library. NULL is a no-op.
        ///
        /// # Safety
        /// `list` must be NULL or an unfreed pointer returned by this
        /// library.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $free(list: *mut $list) {
            crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(list) });
        }
    };
}

/// Generate a fieldless `#[repr(C)]` enum mirror + `From<Ffi>` + no-op
/// `CFree`. Variant names must match the Ffi enum's.
macro_rules! c_enum {
    ($(#[$m:meta])* $name:ident from $ffi:ty { $($(#[$vm:meta])* $v:ident),+ $(,)? }) => {
        crate::macros::c_enum!($(#[$m])* $name { $($(#[$vm])* $v),+ });

        impl From<$ffi> for $name {
            fn from(value: $ffi) -> Self {
                match value { $(<$ffi>::$v => Self::$v),+ }
            }
        }
    };

    // No `Ffi` source: a value only the *caller* produces (a callback's
    // return status), so there is nothing to convert from — just the
    // discriminant validation.
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident),+ $(,)? }) => {
        $(#[$m])*
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($(#[$vm])* $v),+ }

        impl $name {
            /// Validate a caller-supplied discriminant. Enums arrive from C
            /// as `uint32_t`, never as this type: constructing a Rust enum
            /// from an out-of-range integer is undefined behavior before any
            /// guard can run.
            #[allow(dead_code)]
            pub(crate) fn from_c(value: u32) -> Result<Self, crate::MarmotStatus> {
                const VARIANTS: &[$name] = &[$($name::$v),+];
                VARIANTS.get(value as usize).copied().ok_or_else(|| {
                    crate::status::set_last_error(concat!(
                        stringify!($name),
                        " value was out of range"
                    ));
                    crate::MarmotStatus::InvalidArgument
                })
            }
        }

        impl crate::memory::CFree for $name {
            unsafe fn free_in_place(&mut self) {}
        }
    };
}

// Enums with payloads (tagged unions in C) are written by hand: their
// variants are irregular enough that a macro grammar for them costs more
// than it saves.

pub(crate) use {c_enum, c_list, c_mirror};
