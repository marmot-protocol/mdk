package markdown

import "base:runtime"

HelpersLineIter :: struct {
	input: string,
	pos:   int,
}
helpers_lines :: proc(input: string) -> HelpersLineIter {
	return HelpersLineIter{input = input}
}
// Streaming scanner preserving byte offsets and CRLF/bare-CR semantics.
helpers_next_line :: proc(it: ^HelpersLineIter) -> (string, int, bool) {
	if it.pos >= len(it.input) {return "", it.pos, false}
	start := it.pos
	j := start
	for j < len(it.input) {
		if it.input[j] == '\n' || it.input[j] == '\r' {
			step := 1
			if it.input[j] == '\r' && j + 1 < len(it.input) && it.input[j + 1] == '\n' {step = 2}
			it.pos = j + step
			return it.input[start:j], start, true
		}
		j += 1
	}
	it.pos = len(it.input)
	return it.input[start:len(it.input)], start, true
}

helpers_lowercase :: proc(s: string) -> string {
	result: [dynamic]u8
	non_zero_reserve(&result, len(s))
	for r in s {
		// The sole unconditional multi-rune Unicode lowercase mapping.
		if r == 0x130 {
			push(&result, u8('i'), 0xcc, 0x87)
		} else {
			bytes, n := utf8_encode(lowercase_rune(r))
			push(&result, ..bytes[:n])
		}
	}
	return string(result[:])
}
helpers_is_control :: proc(r: rune) -> bool {
	return r >= 0 && r <= 0x1f || r >= 0x7f && r <= 0x9f
}

measure_indent :: proc(s: string) -> (int, int) {
	col, off := 0, 0
	for off < len(s) {
		if s[off] == ' ' {col += 1} else if s[off] == '\t' {col += 4 - col % 4} else {break}
		off += 1
	}
	return col, off
}
is_blank :: proc(s: string) -> bool {
	for b in transmute([]u8)s {if b != ' ' && b != '\t' {return false}}
	return true
}
skip_ws_and_one_newline :: proc(s: string, start: int) -> int {
	i := start
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {i += 1}
	if i < len(s) && s[i] == '\n' {
		i += 1
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {i += 1}
	}
	return i
}
is_ascii_punct :: proc(b: u8) -> bool {
	return(
		b >= '!' && b <= '/' ||
		b >= ':' && b <= '@' ||
		b >= '[' && b <= '`' ||
		b >= '{' && b <= '~' \
	)
}
helpers_alpha :: proc(b: u8) -> bool {return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'}
helpers_alnum :: proc(b: u8) -> bool {return helpers_alpha(b) || b >= '0' && b <= '9'}
helpers_lower :: proc(b: u8) -> u8 {if b >= 'A' && b <= 'Z' {return b + 32}; return b}
helpers_equal_ascii :: proc(a, b: string) -> bool {
	if len(a) != len(b) {return false}
	for i in 0 ..< len(a) {if helpers_lower(a[i]) != helpers_lower(b[i]) {return false}}
	return true
}

// Rust char::is_whitespace (Unicode White_Space), deliberately not ASCII trim.
helpers_whitespace :: proc(r: rune) -> bool {
	return(
		r >= 0x09 && r <= 0x0d ||
		r == 0x20 ||
		r == 0x85 ||
		r == 0xa0 ||
		r == 0x1680 ||
		r >= 0x2000 && r <= 0x200a ||
		r == 0x2028 ||
		r == 0x2029 ||
		r == 0x202f ||
		r == 0x205f ||
		r == 0x3000 \
	)
}
helpers_trim :: proc(s: string) -> string {
	a, b := 0, len(s)
	for a <
	    b {r, n := runtime.string_decode_rune(s[a:b]); if !helpers_whitespace(r) {break}; a += n}
	for a <
	    b {r, n := runtime.string_decode_last_rune(s[a:b]); if !helpers_whitespace(r) {break}; b -= n}
	return s[a:b]
}

entity_decode :: proc(s: string, i: int) -> (string, int, bool) {
	if i < 0 || i + 1 >= len(s) || s[i] != '&' {return "", i, false}
	if s[i + 1] != '#' {
		start := i + 1
		j := start
		for j < len(s) && helpers_alnum(s[j]) {j += 1; if j - start > 32 {return "", i, false}}
		if j == start || j >= len(s) || s[j] != ';' {return "", i, false}
		name := s[start:j]
		lo, hi := 0, len(HELPERS_NAMED)
		for lo < hi {
			mid := lo + (hi - lo) / 2
			if HELPERS_NAMED[mid].name < name {lo = mid + 1} else {hi = mid}
		}
		if lo < len(HELPERS_NAMED) &&
		   HELPERS_NAMED[lo].name == name {return HELPERS_NAMED[lo].value, j + 1, true}
		return "", i, false
	}
	start := i + 2
	hex := start < len(s) && (s[start] == 'x' || s[start] == 'X')
	if hex {start += 1}
	max_digits, base := 7, u32(10)
	if hex {max_digits = 6; base = 16}
	code := u32(0)
	k := start
	for k < len(s) {
		b := s[k]
		digit: u32
		if b >= '0' &&
		   b <=
			   '9' {digit = u32(b - '0')} else if hex && b >= 'a' && b <= 'f' {digit = u32(b - 'a') + 10} else if hex && b >= 'A' && b <= 'F' {digit = u32(b - 'A') + 10} else {break}
		code = code * base + digit
		k += 1
		if k - start > max_digits {return "", i, false}
	}
	if k == start || k >= len(s) || s[k] != ';' {return "", i, false}
	if code <= 8 ||
	   code >= 0x0b && code <= 0x1f ||
	   code >= 0x7f && code <= 0x9f ||
	   code >= 0xd800 && code <= 0xdfff ||
	   code > 0x10ffff {code = 0xfffd}
	bytes, n := utf8_encode(rune(code))
	result := make([]u8, n)
	copy(result, bytes[:n])
	return string(result), k + 1, true
}

BECH32_CHECKSUM_BYTES :: int(6)
MAX_BECH32_BYTES :: int(1024)

// Bit membership for the NIP-19 alphabet: qpzry9x8gf2tvdw0s3jn54khce6mua7l.
@(rodata)
BECH32_DATA_WORDS := [4]u64{0x03fd000000000000, 0x07ff7dfa00000000, 0, 0}

helpers_bech_data :: proc(b: u8) -> bool {
	return BECH32_DATA_WORDS[b >> 6] & (u64(1) << (b & 63)) != 0
}
helpers_boundary :: proc(b: u8) -> bool {return !helpers_alnum(b) && b != '_' && b != '/'}
left_boundary_ok :: proc(s: string, i: int) -> bool {return i == 0 || helpers_boundary(s[i - 1])}
classify_bech32 :: proc(s: string, i: int) -> (NostrHrp, int, bool) {
	if len(s) - i < len("npub1") + BECH32_CHECKSUM_BYTES || s[i] != 'n' {return .Npub, i, false}
	rest := s[i:]
	j := i
	hrp: NostrHrp
	switch s[i + 1] {
	case 'p':
		if text_has_prefix(rest, "npub1") {
			hrp, j = .Npub, i + 5
		} else if text_has_prefix(rest, "nprofile1") {
			hrp, j = .Nprofile, i + 9
		} else {return .Npub, i, false}
	case 'o':
		if !text_has_prefix(rest, "note1") {return .Npub, i, false}
		hrp, j = .Note, i + 5
	case 'e':
		if !text_has_prefix(rest, "nevent1") {return .Npub, i, false}
		hrp, j = .Nevent, i + 7
	case 'a':
		if !text_has_prefix(rest, "naddr1") {return .Npub, i, false}
		hrp, j = .Naddr, i + 6
	case 'r':
		if !text_has_prefix(rest, "nrelay1") {return .Npub, i, false}
		hrp, j = .Nrelay, i + 7
	case:
		return .Npub, i, false
	}
	start := j
	limit := i + min(len(s) - i, MAX_BECH32_BYTES + 1)
	for j < limit && helpers_bech_data(s[j]) {j += 1}
	if j - start < BECH32_CHECKSUM_BYTES ||
	   j - i > MAX_BECH32_BYTES ||
	   j < len(s) && !helpers_boundary(s[j]) {return .Npub, i, false}
	return hrp, j, true
}
helpers_sensitive :: proc(s: string) -> bool {
	secret_prefix :: "ncryptsec1"
	return(
		len(s) >= 5 && helpers_equal_ascii(s[0:5], "nsec1") ||
		len(s) >= len(secret_prefix) &&
			helpers_equal_ascii(s[0:len(secret_prefix)], secret_prefix) \
	)
}
helpers_public :: proc(s: string) -> bool {_, end, ok := classify_bech32(s, 0); return(
		ok &&
		end == len(s) \
	)}
classify_link_destination :: proc(s: string) -> LinkDestinationKind {
	s := helpers_trim(s)
	if helpers_sensitive(s) {return .Sensitive}
	if helpers_public(s) {return .Nostr}
	colon := -1
	for i in 0 ..< len(s) {if s[i] == ':' {colon = i; break}}
	if colon <= 0 || !helpers_alpha(s[0]) {return .Relative}
	scheme := s[0:colon]
	for i in 1 ..< len(scheme) {b := scheme[i]; if !helpers_alnum(b) && b != '+' && b != '-' && b != '.' {return .Relative}}
	if helpers_equal_ascii(scheme, "javascript") ||
	   helpers_equal_ascii(scheme, "data") ||
	   helpers_equal_ascii(scheme, "vbscript") ||
	   helpers_equal_ascii(scheme, "file") {return .Dangerous}
	if helpers_equal_ascii(scheme, "nostr") ||
	   len(scheme) >= 6 && helpers_equal_ascii(scheme[len(scheme) - 6:len(scheme)], "+nostr") {
		body := s[colon + 1:len(s)]
		j := 0
		for j < len(body) && body[j] == '/' {j += 1}
		body = body[j:len(body)]
		if helpers_sensitive(body) {return .Sensitive}
		if helpers_public(body) {return .Nostr}
		return .Unknown
	}
	if helpers_equal_ascii(scheme, "http") || helpers_equal_ascii(scheme, "https") {return .Web}
	if helpers_equal_ascii(scheme, "mailto") ||
	   helpers_equal_ascii(scheme, "tel") {return .Contact}
	if helpers_equal_ascii(scheme, "marmot") ||
	   helpers_equal_ascii(scheme, "whitenoise") ||
	   helpers_equal_ascii(scheme, "whitenoise-staging") {return .App}
	return .Unknown
}
classify_autolink_destination :: proc(s: string, kind: AutolinkKind) -> LinkDestinationKind {
	switch kind {case .Email:
		return .Contact; case .Www:
		return .Web; case .Uri:
		return classify_link_destination(s)}
	unreachable()
}

HelpersNamed :: struct {
	name, value: string,
}

@(rodata)
HELPERS_NAMED := [?]HelpersNamed {
	{"AElig", "Æ"},
	{"Aacute", "Á"},
	{"Acirc", "Â"},
	{"Agrave", "À"},
	{"Aring", "Å"},
	{"Atilde", "Ã"},
	{"Auml", "Ä"},
	{"Ccedil", "Ç"},
	{"ETH", "Ð"},
	{"Eacute", "É"},
	{"Ecirc", "Ê"},
	{"Egrave", "È"},
	{"Euml", "Ë"},
	{"Iacute", "Í"},
	{"Icirc", "Î"},
	{"Igrave", "Ì"},
	{"Iuml", "Ï"},
	{"Ntilde", "Ñ"},
	{"Oacute", "Ó"},
	{"Ocirc", "Ô"},
	{"Ograve", "Ò"},
	{"Oslash", "Ø"},
	{"Otilde", "Õ"},
	{"Ouml", "Ö"},
	{"THORN", "Þ"},
	{"Uacute", "Ú"},
	{"Ucirc", "Û"},
	{"Ugrave", "Ù"},
	{"Uuml", "Ü"},
	{"Yacute", "Ý"},
	{"aacute", "á"},
	{"acirc", "â"},
	{"acute", "´"},
	{"aelig", "æ"},
	{"agrave", "à"},
	{"amp", "&"},
	{"apos", "'"},
	{"aring", "å"},
	{"atilde", "ã"},
	{"auml", "ä"},
	{"brvbar", "¦"},
	{"bull", "•"},
	{"ccedil", "ç"},
	{"cedil", "¸"},
	{"cent", "¢"},
	{"copy", "©"},
	{"curren", "¤"},
	{"deg", "°"},
	{"divide", "÷"},
	{"eacute", "é"},
	{"ecirc", "ê"},
	{"egrave", "è"},
	{"eth", "ð"},
	{"euml", "ë"},
	{"euro", "€"},
	{"frac12", "½"},
	{"frac14", "¼"},
	{"frac34", "¾"},
	{"gt", ">"},
	{"hellip", "…"},
	{"iacute", "í"},
	{"icirc", "î"},
	{"iexcl", "¡"},
	{"igrave", "ì"},
	{"iquest", "¿"},
	{"iuml", "ï"},
	{"laquo", "«"},
	{"ldquo", "“"},
	{"lsquo", "‘"},
	{"lt", "<"},
	{"macr", "¯"},
	{"mdash", "—"},
	{"micro", "µ"},
	{"middot", "·"},
	{"nbsp", " "},
	{"ndash", "–"},
	{"not", "¬"},
	{"ntilde", "ñ"},
	{"oacute", "ó"},
	{"ocirc", "ô"},
	{"ograve", "ò"},
	{"ordf", "ª"},
	{"ordm", "º"},
	{"oslash", "ø"},
	{"otilde", "õ"},
	{"ouml", "ö"},
	{"para", "¶"},
	{"plusmn", "±"},
	{"pound", "£"},
	{"quot", "\""},
	{"raquo", "»"},
	{"rdquo", "”"},
	{"reg", "®"},
	{"rsquo", "’"},
	{"sect", "§"},
	{"shy", "­"},
	{"sup1", "¹"},
	{"sup2", "²"},
	{"sup3", "³"},
	{"szlig", "ß"},
	{"thorn", "þ"},
	{"times", "×"},
	{"trade", "™"},
	{"uacute", "ú"},
	{"ucirc", "û"},
	{"ugrave", "ù"},
	{"uml", "¨"},
	{"uuml", "ü"},
	{"yacute", "ý"},
	{"yen", "¥"},
	{"yuml", "ÿ"},
}
