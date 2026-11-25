#+build windows
package markdown

// LLVM references the MSVC CRT's _fltused marker in objects that use floating point.
// MinGW lacks that marker. @(export) would add a linker directive for its original name.
when #config(MARMOT_MARKDOWN_MINGW, false) {
	@(require, linkage = "strong", link_name = "_fltused")
	_fltused: i32 = 0x9875
}
