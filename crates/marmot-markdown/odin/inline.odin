package markdown


InlineDelim :: struct {
	kind:                u8,
	out_pos, input_pos:  int,
	active:              bool,
	orig_len, len:       int,
	can_open, can_close: bool,
	prev_bracket:        int,
}
InlineNode :: struct {
	item:       Inline,
	prev, next: int,
	alive:      bool,
}
InlineArena :: struct {
	nodes:      [dynamic]InlineNode,
	head, tail: int,
}
InlineDepthFrame :: struct {
	items:        []Inline,
	index, depth: int,
}
InlineTextBuffer :: struct {
	source:   string,
	start:    int,
	decoded:  [dynamic]u8,
	mark:     int,
	decoding: bool,
}

parse_inlines :: proc(doc: ^Document, refs: RefMap) {inline_walk(doc.blocks, refs)}
inline_walk :: proc(blocks: []Block, refs: RefMap) {
	for &b in blocks {
		switch b.tag {
		case .Paragraph, .Heading:
			b.inlines = tokenize(b.inlines, refs)
		case .BlockQuote:
			inline_walk(b.quote.blocks, refs)
		case .List:
			for &item in b.list.items {inline_walk(item.blocks, refs)}
		case .Details:
			if len(b.details.summary) > 0 {b.details.summary = tokenize(b.details.summary, refs)}
			inline_walk(b.details.body, refs)
		case .Table:
			for &cell in b.table.header {cell.inlines = tokenize(cell.inlines, refs)}
			for row in b.table.rows {for &cell in row {cell.inlines = tokenize(cell.inlines, refs)}}
		case .ThematicBreak, .CodeBlock, .MathBlock:
		}
	}
}
inline_has_children :: proc(item: Inline) -> bool {
	return(
		item.tag == .Emph ||
		item.tag == .Strong ||
		item.tag == .Strikethrough ||
		item.tag == .Link ||
		item.tag == .Image \
	)
}
inline_depth :: proc(items: []Inline, depth: int) -> bool {
	if depth >= MAX_INLINE_NESTING_DEPTH {return len(items) > 0}
	// Each pushed frame increases depth; the parser's fixed limit bounds this stack.
	stack: [MAX_INLINE_NESTING_DEPTH]InlineDepthFrame = ---
	stack[0] = InlineDepthFrame{items, 0, depth}
	top := 1
	for top > 0 {
		f := &stack[top - 1]
		if f.index >= len(f.items) {top -= 1; continue}
		item := f.items[f.index]; f.index += 1
		d := f.depth
		if d >= MAX_INLINE_NESTING_DEPTH {return true}
		if inline_has_children(item) {
			if d + 1 >= MAX_INLINE_NESTING_DEPTH {return true}
			children: []Inline
			if item.tag == .Link ||
			   item.tag == .Image {children = item.link.children} else {children = item.children}
			stack[top] = InlineDepthFrame{children, 0, d + 1}; top += 1
		}
	}
	return false
}
inline_coalesce :: proc(items: []Inline) -> []Inline {
	// The graph already owns these slices. Compact forward without copying every node.
	i, written := 0, 0
	for i < len(items) {
		item := items[i]
		#partial switch item.tag {
		case .Emph, .Strong, .Strikethrough:
			item.children = inline_coalesce(item.children)
		case .Link, .Image:
			item.link.children = inline_coalesce(item.link.children)
		}
		if item.tag == .Text {
			j := i + 1; size := len(item.text)
			for j < len(items) && items[j].tag == .Text {size += len(items[j].text); j += 1}
			if j > i + 1 {
				buf: [dynamic]u8; non_zero_reserve(&buf, size)
				for k in i ..< j {push(&buf, ..transmute([]u8)items[k].text)}
				item.text = string(buf[:])
			}
			i = j
		} else {i += 1}
		items[written] = item; written += 1
	}
	return items[:written]
}
inline_decode :: proc(text: ^InlineTextBuffer, at, end: int, value: string) {
	if !text.decoding {
		// Decoding only shrinks source bytes. Reserve once to keep published slices stable.
		if cap(text.decoded) == 0 {non_zero_reserve(&text.decoded, len(text.source))}
		text.mark = len(text.decoded)
		text.decoding = true
	}
	push(&text.decoded, ..transmute([]u8)text.source[text.start:at])
	push(&text.decoded, ..transmute([]u8)value)
	text.start = end
}
inline_flush :: proc(out: ^[dynamic]Inline, text: ^InlineTextBuffer, end: int) {
	if text.decoding {
		push(&text.decoded, ..transmute([]u8)text.source[text.start:end])
		if len(text.decoded) > text.mark {
			push(out, Inline{tag = .Text, text = string(text.decoded[text.mark:])})
		}
		text.decoding = false
	} else if text.start < end {
		push(out, Inline{tag = .Text, text = text.source[text.start:end]})
	}
	text.start = end
}
inline_run_end :: proc(s: string, i: int, ch: u8) -> int {
	j := i; for j < len(s) && s[j] == ch {j += 1}; return j
}
inline_ws :: proc(c: u8) -> bool {return(
		c == ' ' ||
		c == '\t' ||
		c == '\n' ||
		c == '\r' ||
		c == 11 ||
		c == 12 \
	)}
inline_flank :: proc(s: string, i, end: int, ch: u8) -> (bool, bool) {
	pw := i == 0; nw := end == len(s); pp, np := false, false
	if i > 0 {pw = inline_ws(s[i - 1]); pp = is_ascii_punct(s[i - 1])}
	if end < len(s) {nw = inline_ws(s[end]); np = is_ascii_punct(s[end])}
	left := !nw && (!np || pw || pp); right := !pw && (!pp || nw || np)
	if ch == '_' {return left && (!right || pp), right && (!left || np)}
	return left, right
}
inline_code_norm :: proc(s: string) -> string {
	r := s
	if text_contains(s, "\n") {
		b: [dynamic]u8; non_zero_reserve(&b, len(s)); nl := false
		for c in transmute([]u8)s {
			if c == '\n' {if !nl {push(&b, u8(' '))}; nl = true} else {push(&b, c); nl = false}
		}
		r = string(b[:])
	}
	nonspace := false
	for c in transmute([]u8)r {if c != ' ' {nonspace = true; break}}
	if len(r) >= 2 && r[0] == ' ' && r[len(r) - 1] == ' ' && nonspace {return r[1:len(r) - 1]}
	return r
}
inline_math :: proc(s: string, i: int) -> (string, int, int) {
	if i + 1 >= len(s) ||
	   s[i + 1] == '$' ||
	   s[i + 1] == ' ' ||
	   s[i + 1] == '\t' ||
	   s[i + 1] == '\n' {return "", i, 0}
	k := i + 1
	for k < len(s) {
		if s[k] == '\\' && k + 1 < len(s) {k += 2; continue}
		if s[k] == '$' {
			if k + 1 < len(s) && s[k + 1] == '$' {k += 2; continue}
			p := s[k - 1]
			if p != ' ' && p != '\t' && p != '\n' {return s[i + 1:k], k + 1, 1}
		}
		k += 1
	}
	return "", i, -1
}

// A literal run can be represented by its source span until decoding is needed.
inline_literal_end :: proc(s: string, from: int) -> int {
	for c, offset in transmute([]u8)s[from:len(s)] {
		i := from + offset
		if !inline_special(c) {continue}
		if c == '!' && (i + 1 == len(s) || s[i + 1] != '[') {continue}
		if c == 'n' {
			if !left_boundary_ok(s, i) ||
			   (!text_has_prefix(s[i:len(s)], "nostr:") &&
					   !text_has_prefix(s[i:len(s)], "npub1") &&
					   !text_has_prefix(s[i:len(s)], "note1") &&
					   !text_has_prefix(s[i:len(s)], "nevent1") &&
					   !text_has_prefix(s[i:len(s)], "naddr1")) {
				continue
			}
		}
		if c == 'h' || c == 'm' || c == 't' || c == 'w' {
			if !left_boundary_ok(s, i) {continue}
			prefix, _ := inline_bare_prefix(s[i:len(s)])
			if prefix == 0 {continue}
		}
		return i
	}
	return len(s)
}

tokenize :: proc(items: []Inline, refs: RefMap) -> []Inline {
	raw := ""
	if len(items) > 0 && items[0].tag == .Text {raw = items[0].text}
	literal_end := inline_literal_end(raw, 0)
	if literal_end == len(raw) {
		if len(raw) == 0 {return nil}
		return items[:1]
	}
	out: [dynamic]Inline
	pending := InlineTextBuffer {
		source = raw,
	}
	ds: [dynamic]InlineDelim
	last, brackets := -1, 0
	// Index each run's next equal-length run in one reverse pass.
	next_code: IntMap
	code_close: IntMap
	k := len(raw) - 1
	for k >= 0 {
		if raw[k] != '`' {k -= 1; continue}
		end := k + 1
		for k >= 0 && raw[k] == '`' {k -= 1}
		start := k + 1; n := end - start
		if next, ok := int_map_get(next_code, n); ok {
			int_map_set(&code_close, start, next)
		}
		// An escape can consume the first backtick, exposing the remaining run.
		if n > 1 {
			if next, ok := int_map_get(next_code, n - 1); ok {
				int_map_set(&code_close, start + 1, next)
			}
		}
		int_map_set(&next_code, n, start)
	}
	exhausted := false
	i := literal_end
	for i < len(raw) {
		c := raw[i]
		switch c {
		case '\\':
			if i + 1 < len(raw) && raw[i + 1] == '\n' {
				inline_flush(&out, &pending, i); push(&out, Inline{tag = .HardBreak}); i += 2
				for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t') {i += 1}
				pending.start = i
				continue
			}
			if i + 1 < len(raw) &&
			   is_ascii_punct(
				   raw[i + 1],
			   ) {inline_decode(&pending, i, i + 2, raw[i + 1:i + 2]); i += 2; continue}
			i += 1
		case '`':
			end := inline_run_end(raw, i, '`')
			if close, ok := int_map_get(code_close, i); ok {
				inline_flush(&out, &pending, i)
				push(
					&out,
					Inline{tag = .Code, text = inline_code_norm(raw[end:close])},
				); i = close + (end - i)
				pending.start = i
			} else {i = end}
		case '$':
			if !exhausted {
				text, end, state := inline_math(raw, i)
				if state ==
				   1 {inline_flush(&out, &pending, i); push(&out, Inline{tag = .Math, text = text}); i = end; pending.start = i; continue}
				if state == -1 {exhausted = true}
			}
			i += 1
		case '&':
			text, end, ok := entity_decode(raw, i)
			if ok {inline_decode(&pending, i, end, text); i = end} else {i += 1}
		case '[', '!':
			image := c == '!' && i + 1 < len(raw) && raw[i + 1] == '['
			if c == '!' && !image {i += 1; continue}
			width := 1; if image {width = 2}
			if brackets < MAX_INLINE_NESTING_DEPTH {
				inline_flush(&out, &pending, i); pos := len(out)
				push(&out, Inline{tag = .Text, text = raw[i:i + width]})
				push(
					&ds,
					InlineDelim {
						kind = c,
						out_pos = pos,
						input_pos = i + width - 1,
						active = true,
						prev_bracket = last,
					},
				)
				last = len(ds) - 1; brackets += 1
				pending.start = i + width
			}
			i += width
		case '*', '_', '~':
			inline_flush(&out, &pending, i); end := inline_run_end(raw, i, c)
			op, cl := inline_flank(raw, i, end, c)
			push(
				&ds,
				InlineDelim {
					kind = c,
					out_pos = len(out),
					input_pos = i,
					active = true,
					orig_len = end - i,
					len = end - i,
					can_open = op,
					can_close = cl,
					prev_bracket = -1,
				},
			)
			push(&out, Inline{tag = .Text, text = raw[i:end]}); i = end; pending.start = i
		case ']':
			inline_flush(&out, &pending, i)
			end, ok := inline_close(raw, i, &out, &ds, &last, &brackets, refs)
			if ok {i = end; pending.start = i} else {i += 1}
		case '<':
			item, end, ok := inline_angle(raw, i)
			if ok {inline_flush(&out, &pending, i); push(&out, item); i = end; pending.start = i} else {i += 1}
		case '@', 'n':
			item, end, ok := inline_nostr(raw, i)
			if ok {inline_flush(&out, &pending, i); push(&out, item); i = end; pending.start = i} else {i += 1}
		case 'h', 'm', 't', 'w':
			item, end, ok := inline_bare(raw, i)
			if ok {inline_flush(&out, &pending, i); push(&out, item); i = end; pending.start = i} else {i += 1}
		case '\n':
			trailing := 0
			end := i
			if pending.decoding {
				push(&pending.decoded, ..transmute([]u8)raw[pending.start:i]); pending.start = i
				for p := len(pending.decoded) - 1;
				    p >= pending.mark && pending.decoded[p] == ' ';
				    p -= 1 {trailing += 1}
				for len(pending.decoded) > pending.mark &&
				    (pending.decoded[len(pending.decoded) - 1] == ' ' ||
						    pending.decoded[len(pending.decoded) - 1] ==
							    '\t') {resize(&pending.decoded, len(pending.decoded) - 1)}
			} else {
				for p := i - 1; p >= pending.start && raw[p] == ' '; p -= 1 {trailing += 1}
				for end > pending.start && (raw[end - 1] == ' ' || raw[end - 1] == '\t') {end -= 1}
			}
			inline_flush(&out, &pending, end)
			tag: InlineKind = .SoftBreak; if trailing >= 2 {tag = .HardBreak}
			push(&out, Inline{tag = tag}); i += 1
			for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t') {i += 1}
			pending.start = i
		case:
			i = inline_literal_end(raw, i + 1)
		}
	}
	inline_flush(&out, &pending, len(raw)); inline_emphasis(&out, ds[:], 0)
	return inline_coalesce(out[:])
}

inline_prev_bracket :: proc(ds: []InlineDelim, cursor: int) -> int {
	c := cursor
	for c >= 0 &&
	    c <
		    len(
			    ds,
		    ) {if ds[c].active && (ds[c].kind == '[' || ds[c].kind == '!') {return c}; c = ds[c].prev_bracket}
	return -1
}
inline_bracket_state :: proc(ds: []InlineDelim, last, count: ^int) {
	last^ = inline_prev_bracket(ds, last^); count^ = 0; c := last^
	for c >= 0 {count^ += 1; c = inline_prev_bracket(ds, ds[c].prev_bracket)}
}
inline_label :: proc(s: string) -> string {
	if len(s) > 999 {return ""}
	if !text_contains(s, "\\") {return s}
	b: [dynamic]u8; non_zero_reserve(&b, len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i + 1 < len(s) {i += 1}
		// Copy complete UTF-8 by bytes; backslash itself is ASCII.
		push(&b, s[i]); i += 1
	}
	return string(b[:])
}
inline_suffix :: proc(s: string, i: int) -> (LinkRef, int, bool) {
	j := skip_ws_and_one_newline(s, i + 1)
	dest, end, ok := parse_link_destination(s, j)
	if ok {j = end} else {dest = ""}
	j = skip_ws_and_one_newline(s, j)
	def := LinkRef {
		dest = dest,
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'' || s[j] == '(') {
		title, te, tok := parse_link_title(s, j)
		if tok {def.title = title; def.has_title = true; j = skip_ws_and_one_newline(s, te)}
	}
	if j >= len(s) || s[j] != ')' {return {}, i, false}
	return def, j + 1, true
}
inline_ref_label :: proc(s: string, i: int) -> (string, int, bool) {
	j := i + 1; start := j
	for j < len(s) && s[j] != ']' {
		if s[j] == '\\' && j + 1 < len(s) {j += 2; continue}
		if s[j] == '[' {return "", i, false}
		j += 1; if j - start > 999 {return "", i, false}
	}
	if j >= len(s) {return "", i, false}; return s[start:j], j + 1, true
}
inline_close :: proc(
	s: string,
	i: int,
	out: ^[dynamic]Inline,
	ds: ^[dynamic]InlineDelim,
	last, count: ^int,
	refs: RefMap,
) -> (
	int,
	bool,
) {
	op := inline_prev_bracket(ds^[:], last^)
	if op < 0 {return i, false}; last^ = op
	d := ds^[op]
	def: LinkRef; end := i + 1; found := false
	if i + 1 < len(s) && s[i + 1] == '(' {def, end, found = inline_suffix(s, i + 1)}
	if !found && refs.count > 0 && i + 1 < len(s) && s[i + 1] == '[' {
		label, re, ok := inline_ref_label(s, i + 1)
		if ok {
			if len(helpers_trim(label)) >
			   0 {def, found = ref_map_get(refs, normalize_label(label))}
			if len(label) ==
			   0 {def, found = ref_map_get(refs, normalize_label(inline_label(s[d.input_pos + 1:i])))}
			if found {end = re}
		}
	}
	if !found && refs.count > 0 {
		label := inline_label(s[d.input_pos + 1:i])
		if len(label) > 0 {def, found = ref_map_get(refs, normalize_label(label)); end = i + 1}
	}
	if found && inline_absorb(out, ds, op, def, last, count) {return end, true}
	ds^[op].active = false; inline_bracket_state(ds^[:], last, count)
	return i, false
}
inline_absorb :: proc(
	out: ^[dynamic]Inline,
	ds: ^[dynamic]InlineDelim,
	op: int,
	def: LinkRef,
	last, count: ^int,
) -> bool {
	inline_emphasis(out, ds^[:], op + 1); inline_bracket_state(ds^[:], last, count)
	d := ds^[op]
	children := out^[d.out_pos + 1:]
	if inline_depth(children, 1) {return false}
	owned: [dynamic]Inline; non_zero_reserve(&owned, len(children)); push(&owned, ..children)
	resize(out, d.out_pos)
	tag: InlineKind = .Link; if d.kind == '!' {tag = .Image}
	push(
		out,
		Inline {
			tag = tag,
			link = LinkPayload{dest = def.dest, title = def.title, children = owned[:]},
			has_title = def.has_title,
			classification = classify_link_destination(def.dest),
		},
	)
	resize(ds, op)
	c := inline_prev_bracket(ds^[:], d.prev_bracket)
	if tag == .Link {
		for c >=
		    0 {prev := ds^[c].prev_bracket; if ds^[c].kind == '[' {ds^[c].active = false}; c = inline_prev_bracket(ds^[:], prev)}
	}
	last^ = d.prev_bracket; inline_bracket_state(ds^[:], last, count)
	return true
}

inline_alpha :: proc(c: u8) -> bool {return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')}
inline_digit :: proc(c: u8) -> bool {return c >= '0' && c <= '9'}
inline_alnum :: proc(c: u8) -> bool {return inline_alpha(c) || inline_digit(c)}
inline_angle :: proc(s: string, i: int) -> (Inline, int, bool) {
	if text_has_prefix(s[i:len(s)], "<t:") {
		j := i + 3; neg := false
		if j < len(s) && s[j] == '-' {neg = true; j += 1}
		start := j; value: u64 = 0; valid := true
		limit := u64(0x7fff_ffff_ffff_ffff); if neg {limit += 1}
		for j < len(s) && inline_digit(s[j]) {
			digit := u64(s[j] - '0')
			if value > (limit - digit) / 10 {valid = false} else {value = value * 10 + digit}
			j += 1
		}
		style: TimestampStyle = .ShortDateTime
		if j < len(s) && s[j] == ':' {
			j += 1
			if j >= len(s) {valid = false} else {
				switch s[j] {
				case 't':
					style = .ShortTime
				case 'T':
					style = .LongTime
				case 'd':
					style = .ShortDate
				case 'D':
					style = .LongDate
				case 'f':
					style = .ShortDateTime
				case 'F':
					style = .LongDateTime
				case 's':
					style = .CompactDateTime
				case 'S':
					style = .CompactDateTimeSeconds
				case 'R':
					style = .Relative
				case:
					valid = false
				}; j += 1
			}
		}
		if valid &&
		   j > start &&
		   start < len(s) &&
		   inline_digit(s[start]) &&
		   j < len(s) &&
		   s[j] == '>' {
			seconds := transmute(i64)value
			if neg {seconds = transmute(i64)(u64(0) - value)}
			return Inline{tag = .Timestamp, unix_seconds = seconds, style = style}, j + 1, true
		}
	}
	start := i + 1; j := start
	if j < len(s) && inline_alpha(s[j]) {
		j += 1
		for j < len(s) &&
		    j - start < 32 &&
		    (inline_alnum(s[j]) || s[j] == '+' || s[j] == '.' || s[j] == '-') {j += 1}
		if j - start >= 2 && j < len(s) && s[j] == ':' {
			j += 1
			for j < len(s) && s[j] != '>' {
				if s[j] == '<' || s[j] <= 32 || s[j] == 127 {break}; j += 1
			}
			if j < len(s) && s[j] == '>' {return inline_auto(s[start:j], .Uri), j + 1, true}
		}
	}
	j = start
	for j < len(s) &&
	    (inline_alnum(s[j]) || text_contains(".!#$%&'*+/=?^_`{|}~-", s[j:j + 1])) {j += 1}
	if j == start || j >= len(s) || s[j] != '@' {return {}, i, false}
	j += 1
	for {
		label := j
		if j >= len(s) || !inline_alnum(s[j]) {return {}, i, false}; j += 1
		for j < len(s) && j - label < 63 && (inline_alnum(s[j]) || s[j] == '-') {j += 1}
		if s[j - 1] == '-' {return {}, i, false}
		if j < len(s) && s[j] == '.' {j += 1; continue}; break
	}
	if j < len(s) && s[j] == '>' {return inline_auto(s[start:j], .Email), j + 1, true}
	return {}, i, false
}
inline_auto :: proc(url: string, kind: AutolinkKind) -> Inline {
	return Inline {
		tag = .Autolink,
		text = url,
		autolink_kind = kind,
		classification = classify_autolink_destination(url, kind),
	}
}

@(linkage = "internal")
inline_special :: proc(c: u8) -> bool {
	switch c {
	case '\\',
	     '`',
	     '$',
	     '&',
	     '[',
	     '!',
	     '*',
	     '_',
	     '~',
	     ']',
	     '<',
	     '@',
	     'n',
	     'h',
	     'm',
	     't',
	     'w',
	     '\n':
		return true
	case:
		return false
	}
}

inline_bare_prefix :: proc(s: string) -> (int, AutolinkKind) {
	if len(s) == 0 {return 0, .Uri}
	switch s[0] {
	case 'h':
		if text_has_prefix(s, "https://") {return len("https://"), .Uri}
		if text_has_prefix(s, "http://") {return len("http://"), .Uri}
	case 'm':
		if text_has_prefix(s, "mailto:") {return len("mailto:"), .Uri}
		if text_has_prefix(s, "marmot://") {return len("marmot://"), .Uri}
	case 't':
		if text_has_prefix(s, "tel:") {return len("tel:"), .Uri}
	case 'w':
		if text_has_prefix(s, "www.") {return len("www."), .Www}
		if text_has_prefix(s, "whitenoise-staging://") {return len("whitenoise-staging://"), .Uri}
		if text_has_prefix(s, "whitenoise://") {return len("whitenoise://"), .Uri}
	}
	return 0, .Uri
}

inline_bare :: proc(s: string, i: int) -> (Inline, int, bool) {
	if !left_boundary_ok(s, i) || (i > 0 && s[i - 1] == '<') {return {}, i, false}
	n, kind := inline_bare_prefix(s[i:len(s)])
	if n == 0 {return {}, i, false}
	start := i + n; j := start; opens, closes := 0, 0
	for j < len(s) && s[j] > 32 && s[j] != 127 && s[j] != '<' && s[j] != '>' {
		if s[j] == '(' {opens += 1}; if s[j] == ')' {closes += 1}; j += 1
	}
	for j > start {
		c := s[j - 1]
		if text_contains(".,;:!?*_~", s[j - 1:j]) {j -= 1; continue}
		if c == ')' && closes > opens {j -= 1; closes -= 1; continue}; break
	}
	if j == start {return {}, i, false}; return inline_auto(s[i:j], kind), j, true
}
inline_nostr :: proc(s: string, i: int) -> (Inline, int, bool) {
	if !left_boundary_ok(s, i) {return {}, i, false}
	start := i; tag: InlineKind = .NostrMention; uri := false
	if s[i] ==
	   '@' {start += 1} else if text_has_prefix(s[i:len(s)], "nostr:") {start += 6; tag = .NostrUri; uri = true} else {
		if (i > 0 && s[i - 1] == '@') || (i >= 6 && s[i - 6:i] == "nostr:") {return {}, i, false}
	}
	hrp, end, ok := classify_bech32(s, start)
	if !ok {return {}, i, false}
	if !uri && hrp != .Npub {
		if s[i] == '@' || (hrp != .Note && hrp != .Nevent && hrp != .Naddr) {return {}, i, false}
		if !bech32_checksum_ok(s[start:end]) {return {}, i, false}
		tag = .NostrUri
	}
	return Inline{tag = tag, text = s[start:end], hrp = hrp}, end, true
}

inline_arena_unlink :: proc(a: ^InlineArena, idx: int) {
	if !a.nodes[idx].alive {return}
	p := a.nodes[idx].prev; n := a.nodes[idx].next
	if p >= 0 {a.nodes[p].next = n} else {a.head = n}
	if n >= 0 {a.nodes[n].prev = p} else {a.tail = p}
	a.nodes[idx].prev = -1; a.nodes[idx].next = -1; a.nodes[idx].alive = false
}
inline_arena_insert :: proc(a: ^InlineArena, p, n: int, item: Inline) {
	idx := len(a.nodes); push(&a.nodes, InlineNode{item, p, n, true})
	if p >= 0 {a.nodes[p].next = idx} else {a.head = idx}
	if n >= 0 {a.nodes[n].prev = idx} else {a.tail = idx}
}
inline_delim_unlink :: proc(ds: []InlineDelim, prev, next: []int, idx: int) {
	if !ds[idx].active {return}
	p := prev[idx]; n := next[idx]
	if p >= 0 {next[p] = n}; if n >= 0 {prev[n] = p}
	prev[idx] = -1; next[idx] = -1; ds[idx].active = false
}
inline_emphasis :: proc(out: ^[dynamic]Inline, ds: []InlineDelim, bottom: int) {
	if len(out^) == 0 || bottom >= len(ds) {return}
	ds := ds[bottom:]
	bottom := 0
	first := -1; arena_start := len(out^)
	for idx in bottom ..< len(ds) {if ds[idx].active {if first < 0 {first = idx}; arena_start = min(arena_start, ds[idx].out_pos)}}
	if first < 0 {return}
	prev_storage, next_storage: [dynamic]int
	non_zero_resize(&prev_storage, len(ds)); non_zero_resize(&next_storage, len(ds))
	prev, next := prev_storage[:], next_storage[:]
	for idx in 0 ..< len(ds) {prev[idx] = -1; next[idx] = -1}
	last := -1
	for idx in bottom ..< len(ds) {
		if !ds[idx].active {continue}
		prev[idx] = last; if last >= 0 {next[last] = idx}; last = idx
		ds[idx].out_pos -= arena_start
	}
	a := InlineArena {
		head = 0,
		tail = len(out^) - arena_start - 1,
	}
	non_zero_reserve(&a.nodes, len(out^) - arena_start)
	for item, idx in out^[arena_start:] {
		n := idx + 1; if idx == a.tail {n = -1}
		push(&a.nodes, InlineNode{item, idx - 1, n, true})
	}
	resize(out, arena_start)
	EmphBucket :: enum {
		Star,
		Underscore,
		Tilde,
	}
	// Only these three delimiter kinds need opener search state.
	bottoms: [EmphBucket][2][3]int
	cursor := first
	for cursor >= 0 {
		ci := cursor; cl := ds[ci]
		if !(cl.kind == '*' || cl.kind == '_' || cl.kind == '~') ||
		   !cl.can_close ||
		   !cl.active {cursor = next[ci]; continue}
		bucket: EmphBucket = .Star
		if cl.kind == '_' {bucket = .Underscore} else if cl.kind == '~' {bucket = .Tilde}
		can := 0; if cl.can_open {can = 1}
		low := bottoms[bucket][can][cl.orig_len % 3]
		oi := -1; k := prev[ci]
		for k >= 0 && k >= low {
			op := ds[k]
			if op.kind == '[' || op.kind == '!' {break}
			compatible := op.active && op.kind == cl.kind && op.can_open
			if compatible && op.kind == '~' && (op.len < 2 || cl.len < 2) {compatible = false}
			if compatible &&
			   op.kind != '~' &&
			   (op.can_close || cl.can_open) &&
			   (op.orig_len + cl.orig_len) % 3 == 0 &&
			   !(op.orig_len % 3 == 0 && cl.orig_len % 3 == 0) {compatible = false}
			if compatible {oi = k; break}; k = prev[k]
		}
		if oi < 0 {
			bottoms[bucket][can][cl.orig_len % 3] = ci; cursor = next[ci]
			if !cl.can_open {inline_delim_unlink(ds, prev, next, ci)}; continue
		}
		op :=
			ds[oi]; strong := op.len >= 2 && cl.len >= 2; n := 1; if cl.kind == '~' || strong {n = 2}
		too_deep := false; child_count := 0; node := a.nodes[op.out_pos].next
		for node >= 0 && node != cl.out_pos {
			item := a.nodes[node].item
			if inline_has_children(item) {
				children: []Inline
				if item.tag == .Link ||
				   item.tag ==
					   .Image {children = item.link.children} else {children = item.children}
				if inline_depth(children, 2) {too_deep = true; break}
			}
			child_count += 1
			node = a.nodes[node].next
		}
		if too_deep {
			bottoms[bucket][can][cl.orig_len % 3] = ci; cursor = next[ci]
			if !cl.can_open {inline_delim_unlink(ds, prev, next, ci)}; continue
		}
		children: [dynamic]Inline; non_zero_reserve(&children, child_count); node = a.nodes[op.out_pos].next
		for node >= 0 && node != cl.out_pos {
			nn :=
				a.nodes[node].next; push(&children, a.nodes[node].item); inline_arena_unlink(&a, node); node = nn
		}
		a.nodes[op.out_pos].item.text = a.nodes[op.out_pos].item.text[0:op.len - n]
		a.nodes[cl.out_pos].item.text = a.nodes[cl.out_pos].item.text[n:len(
			a.nodes[cl.out_pos].item.text,
		)]
		tag: InlineKind = .Emph; if cl.kind == '~' {tag = .Strikethrough} else if strong {tag = .Strong}
		p := op.out_pos; nn := a.nodes[p].next
		if op.len == n {p = a.nodes[op.out_pos].prev; inline_arena_unlink(&a, op.out_pos)}
		inline_arena_insert(&a, p, nn, Inline{tag = tag, children = children[:]})
		if cl.len == n {inline_arena_unlink(&a, cl.out_pos)}
		ds[oi].len -= n; ds[ci].len -= n
		after := next[ci]; k = next[oi]
		for k >= 0 && k != ci {nk := next[k]; inline_delim_unlink(ds, prev, next, k); k = nk}
		if ds[oi].len > 0 {cursor = oi} else if ds[ci].len > 0 {cursor = ci} else {cursor = after}
		if ds[oi].len == 0 {inline_delim_unlink(ds, prev, next, oi)}
		if ds[ci].len == 0 {inline_delim_unlink(ds, prev, next, ci)}
	}
	positions: [dynamic]int; non_zero_resize(&positions, len(a.nodes)); for &p in positions {p = -1}
	node := a.head
	for node >= 0 {
		if a.nodes[node].alive {positions[node] = len(out^) - arena_start; push(out, a.nodes[node].item)}
		node = a.nodes[node].next
	}
	for idx in bottom ..< len(ds) {
		if !ds[idx].active {continue}
		pos := ds[idx].out_pos
		if pos < len(positions) &&
		   positions[pos] >=
			   0 {ds[idx].out_pos = arena_start + positions[pos]} else {ds[idx].active = false}
	}
}
