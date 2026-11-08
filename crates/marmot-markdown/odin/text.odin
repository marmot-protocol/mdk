#+private
package markdown

text_has_prefix :: proc "contextless" (s, prefix: string) -> bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

text_contains :: proc "contextless" (s, needle: string) -> bool {
	if len(needle) == 0 {return true}
	if len(needle) > len(s) {return false}
	for i in 0 ..= len(s) - len(needle) {
		if s[i] == needle[0] && s[i:i + len(needle)] == needle {return true}
	}
	return false
}
utf8_encode :: proc "contextless" (r: rune) -> ([4]u8, int) {
	code := u32(r)
	if code > 0x10ffff || code >= 0xd800 && code <= 0xdfff {code = 0xfffd}
	bytes: [4]u8
	if code <= 0x7f {
		bytes[0] = u8(code)
		return bytes, 1
	}
	if code <= 0x7ff {
		bytes[0] = 0xc0 | u8(code >> 6)
		bytes[1] = 0x80 | u8(code & 0x3f)
		return bytes, 2
	}
	if code <= 0xffff {
		bytes[0] = 0xe0 | u8(code >> 12)
		bytes[1] = 0x80 | u8((code >> 6) & 0x3f)
		bytes[2] = 0x80 | u8(code & 0x3f)
		return bytes, 3
	}
	bytes[0] = 0xf0 | u8(code >> 18)
	bytes[1] = 0x80 | u8((code >> 12) & 0x3f)
	bytes[2] = 0x80 | u8((code >> 6) & 0x3f)
	bytes[3] = 0x80 | u8(code & 0x3f)
	return bytes, 4
}
