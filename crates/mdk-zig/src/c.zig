/// Raw C bindings imported from the mdk.h header.
///
/// Prefer using the high-level `mdk` module instead of calling these directly.
pub const c = @cImport({
    @cInclude("mdk.h");
});
