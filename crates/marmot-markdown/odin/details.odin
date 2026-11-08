package markdown

// Bounded structural tag recognition over original source. Test builds count
// scan and collector work without adding instrumentation to production parsing.
MAX_DETAILS_TAG_BYTES :: 4096
MAX_DETAILS_SCAN_BYTES :: 65536

@(thread_local)
details_work: u64

@(disabled = !ODIN_TEST)
details_work_reset :: proc() {details_work = 0}
details_work_get :: proc() -> u64 {return details_work}
@(disabled = !ODIN_TEST)
details_charge :: proc(n: int) {
	amount := u64(n)
	if max(u64) - details_work < amount {details_work = max(u64)} else {details_work += amount}
}

details_window :: proc(input: string) -> int {
	return details_floor_boundary(input, min(len(input), MAX_DETAILS_SCAN_BYTES))
}

DetailsOpen :: struct {
	open:    bool,
	tag_end: int,
}
DetailsClose :: struct {
	tag_end: int,
}
SummaryLineKind :: enum {
	NotSummary,
	Complete,
	OpenOnly,
	Malformed,
}
SummaryLine :: struct {
	kind:       SummaryLineKind,
	inner:      string,
	after_open: string,
}
SummaryContinueKind :: enum {
	Complete,
	StillOpen,
	Malformed,
}
SummaryContinue :: struct {
	kind:  SummaryContinueKind,
	inner: string,
}
DetailsDeferred :: struct {
	rel_start, tag_end: int,
	trailing_ws_only:   bool,
}
DetailsTick :: struct {
	start, length: int,
}
SummaryCollector :: struct {
	bytes:               [dynamic]u8,
	unmatched:           [dynamic]DetailsTick,
	unmatched_by_length: IntMap,
	deferred_closers:    [dynamic]DetailsDeferred,
}

summary_collector_new :: proc() -> SummaryCollector {
	return SummaryCollector{}
}
summary_collector_from :: proc(after_open: string) -> SummaryCollector {
	c := summary_collector_new()
	summary_push_segment(&c, after_open, max(int), true)
	return c
}
summary_inner :: proc(c: ^SummaryCollector) -> string {return string(c.bytes[:])}
summary_has_unmatched :: proc(c: ^SummaryCollector) -> bool {return len(c.unmatched) != 0}
summary_push_line :: proc(
	c: ^SummaryCollector,
	next_line: string,
	max_bytes: int,
) -> SummaryContinue {
	details_charge(1)
	next, _ := details_trim_leading(next_line)
	if len(next) > 0 && next[0] == '<' && summary_looks_open(next) {
		return SummaryContinue{kind = .Malformed}
	}
	return summary_push_segment(c, next, max_bytes, false)
}
summary_finalize :: proc(c: ^SummaryCollector) -> (inner: string, leftovers: []string, ok: bool) {
	for closer in c.deferred_closers {
		if !closer.trailing_ws_only {continue}
		text := summary_inner(c)
		if closer.rel_start > len(text) || closer.tag_end > len(text) {return "", nil, false}
		lines: [dynamic]string
		start := closer.tag_end
		// The portion of the closer's own line is not a body line.
		for start < len(text) && text[start] != '\n' {start += 1}
		if start < len(text) {
			start += 1
			for i := start; i <= len(text); i += 1 {
				if i == len(text) || text[i] == '\n' {
					push(&lines, text[start:i])
					start = i + 1
				}
			}
		}
		return text[0:summary_inner_end(closer.rel_start, text)], lines[:], true
	}
	return "", nil, false
}
summary_push_segment :: proc(
	c: ^SummaryCollector,
	text: string,
	max_bytes: int,
	first: bool,
) -> SummaryContinue {
	take := details_floor_boundary(text, min(len(text), max_bytes))
	sliced := text[0:take]
	join := !first && len(c.bytes) > 0
	from := len(c.bytes)
	if join {from += 1}
	details_charge(len(sliced) + int(join))
	if join {push(&c.bytes, '\n')}
	push(&c.bytes, ..transmute([]u8)sliced)
	kind, rel_start, tag_end := summary_scan_from(c, from)
	switch kind {
	case .Found:
		inner := summary_inner(c)
		if !details_trailing_ws(inner, tag_end) {return SummaryContinue{kind = .Malformed}}
		return SummaryContinue {
			kind = .Complete,
			inner = inner[:summary_inner_end(rel_start, inner)],
		}
	case .Absent:
		return SummaryContinue{kind = .StillOpen}
	case .Malformed:
		return SummaryContinue{kind = .Malformed}
	}
	unreachable()
}
DetailsCloseSeek :: enum {
	Found,
	Absent,
	Malformed,
}
summary_scan_from :: proc(c: ^SummaryCollector, from: int) -> (DetailsCloseSeek, int, int) {
	text := summary_inner(c)
	limit := len(text)
	i := from
	for i < limit {
		details_charge(1)
		if text[i] == '`' {
			end := i
			for end < limit && text[end] == '`' {details_charge(1); end += 1}
			run_len := end - i
			details_charge(1)
			if opener_index, found := int_map_get(c.unmatched_by_length, run_len); found {
				opener_start := c.unmatched[opener_index].start
				for len(c.unmatched) > opener_index {
					details_charge(1)
					last := pop(&c.unmatched)
					int_map_delete(&c.unmatched_by_length, last.length)
				}
				for len(c.deferred_closers) > 0 &&
				    c.deferred_closers[len(c.deferred_closers) - 1].rel_start > opener_start {
					details_charge(1)
					pop(&c.deferred_closers)
				}
			} else {
				int_map_set(&c.unmatched_by_length, run_len, len(c.unmatched))
				push(&c.unmatched, DetailsTick{i, run_len})
			}
			i = end
			continue
		}
		if text[i] == '<' &&
		   details_byte_is(text, i + 1, '/') &&
		   details_match_name(text[i + 2:len(text)], "summary") {
			j := i + 2 + len("summary")
			if details_tag_boundary(text, j) {
				j = details_skip_ws(text, j)
				if details_byte_is(text, j, '>') {
					tag_end := j + 1
					if tag_end - i > MAX_DETAILS_TAG_BYTES {return .Malformed, 0, 0}
					if len(c.unmatched) > 0 {
						push(
							&c.deferred_closers,
							DetailsDeferred{i, tag_end, details_trailing_ws(text, tag_end)},
						)
						i = tag_end
						continue
					}
					return .Found, i, tag_end
				}
				return .Malformed, 0, 0
			}
		}
		i += 1
	}
	return .Absent, 0, 0
}
summary_inner_end :: proc(start: int, inner: string) -> int {
	if start > 0 && inner[start - 1] == '\n' {return start - 1}
	return start
}
details_trailing_ws :: proc(text: string, from: int) -> bool {
	for i := from; i < len(text) && text[i] != '\n' && text[i] != '\r'; i += 1 {
		if text[i] != ' ' && text[i] != '\t' {return false}
	}
	return true
}

parse_details_opener_line :: proc(line: string) -> (DetailsOpen, bool) {
	details_charge(1)
	body, start := details_trim_line(line)
	if len(body) == 0 || body[0] != '<' {return {}, false}
	parsed, ok := details_parse_open(body, "details")
	if !ok ||
	   parsed.self_closing ||
	   !details_only_ws(body[parsed.tag_end:len(body)]) {return {}, false}
	return DetailsOpen{parsed.has_open_attr, start + parsed.tag_end}, true
}
parse_details_closer_line :: proc(line: string) -> (DetailsClose, bool) {
	details_charge(1)
	body, start := details_trim_line(line)
	if len(body) == 0 || body[0] != '<' {return {}, false}
	tag_end, ok := details_parse_close(body, "details")
	if !ok || !details_only_ws(body[tag_end:len(body)]) {return {}, false}
	return DetailsClose{start + tag_end}, true
}
parse_summary_line :: proc(line: string) -> SummaryLine {
	return parse_summary_line_bounded(line, max(int))
}
parse_summary_line_bounded :: proc(line: string, max_bytes: int) -> SummaryLine {
	details_charge(1)
	body, _ := details_trim_leading(line)
	if len(body) == 0 || body[0] != '<' {return SummaryLine{kind = .NotSummary}}
	open, ok := details_parse_open(body, "summary")
	if !ok {
		if summary_looks_open(body) {return SummaryLine{kind = .Malformed}}
		return SummaryLine{kind = .NotSummary}
	}
	if open.self_closing {return SummaryLine{kind = .Malformed}}
	budget := max(0, max_bytes - open.tag_end)
	c := summary_collector_new()
	result := summary_push_segment(&c, body[open.tag_end:len(body)], budget, true)
	switch result.kind {
	case .Complete:
		return SummaryLine{kind = .Complete, inner = result.inner}
	case .StillOpen:
		return SummaryLine{kind = .OpenOnly, after_open = summary_inner(&c)}
	case .Malformed:
		return SummaryLine{kind = .Malformed}
	}
	unreachable()
}
continue_summary :: proc(accumulated, next_line: string) -> SummaryContinue {
	return continue_summary_bounded(accumulated, next_line, max(int))
}
continue_summary_bounded :: proc(
	accumulated, next_line: string,
	max_bytes: int,
) -> SummaryContinue {
	c := summary_collector_from(accumulated)
	return summary_push_line(&c, next_line, max_bytes)
}
summary_looks_open :: proc(body: string) -> bool {
	return len(body) > 0 && body[0] == '<' && details_match_name(body[1:len(body)], "summary")
}
DetailsParsedOpen :: struct {
	tag_end:                     int,
	has_open_attr, self_closing: bool,
}
details_parse_open :: proc(text, name: string) -> (DetailsParsedOpen, bool) {
	if len(text) == 0 || text[0] != '<' || details_byte_is(text, 1, '/') {return {}, false}
	if !details_match_name(text[1:len(text)], name) {return {}, false}
	i := 1 + len(name)
	if !details_tag_boundary(text, i) {return {}, false}
	has_open, self_closing := false, false
	for {
		if i > MAX_DETAILS_TAG_BYTES {return {}, false}
		details_charge(1)
		i = details_skip_ws(text, i)
		if i >= len(text) || i + 1 > MAX_DETAILS_TAG_BYTES {return {}, false}
		switch text[i] {
		case '>':
			return DetailsParsedOpen{i + 1, has_open, self_closing}, true
		case '/':
			self_closing = true
			i = details_skip_ws(text, i + 1)
			if !details_byte_is(text, i, '>') || i + 1 > MAX_DETAILS_TAG_BYTES {return {}, false}
			return DetailsParsedOpen{i + 1, has_open, self_closing}, true
		case:
			end, is_open, ok := details_parse_attr(text, i)
			if !ok || end > MAX_DETAILS_TAG_BYTES {return {}, false}
			if is_open {has_open = true}
			i = end
		}
	}
}
details_parse_close :: proc(text, name: string) -> (int, bool) {
	if len(text) < 2 ||
	   text[0] != '<' ||
	   text[1] != '/' ||
	   !details_match_name(text[2:len(text)], name) {return 0, false}
	i := 2 + len(name)
	if !details_tag_boundary(text, i) {return 0, false}
	i = details_skip_ws(text, i)
	if !details_byte_is(text, i, '>') || i + 1 > MAX_DETAILS_TAG_BYTES {return 0, false}
	details_charge(i + 1)
	return i + 1, true
}
details_parse_attr :: proc(text: string, start: int) -> (int, bool, bool) {
	if start >= len(text) || !details_is_alpha(text[start]) {return 0, false, false}
	i := start + 1
	for i < len(text) && details_attr_continue(text[i]) {i += 1}
	name := text[start:i]
	is_open := len(name) == 4 && details_match_name(name, "open")
	i = details_skip_ws(text, i)
	if !details_byte_is(text, i, '=') {return i, is_open, true}
	i = details_skip_ws(text, i + 1)
	if i >= len(text) {return 0, false, false}
	switch text[i] {
	case '"', '\'':
		quote := text[i]
		i += 1
		for i < len(text) && text[i] != quote {
			details_charge(1)
			i += 1
			if i - start + 1 > MAX_DETAILS_TAG_BYTES {return 0, false, false}
		}
		if i >= len(text) {return 0, false, false}
		return i + 1, is_open, true
	case '>', '/':
		return 0, false, false
	case:
		val_start := i
		for i < len(text) &&
		    text[i] != ' ' &&
		    text[i] != '\t' &&
		    text[i] != '>' &&
		    text[i] != '/' {
			details_charge(1)
			i += 1
			if i - start + 1 > MAX_DETAILS_TAG_BYTES {return 0, false, false}
		}
		if i == val_start {return 0, false, false}
		return i, is_open, true
	}
}
details_floor_boundary :: proc(s: string, end: int) -> int {
	i := min(end, len(s))
	for i > 0 && i < len(s) && s[i] & 0xc0 == 0x80 {i -= 1}
	return i
}
details_match_name :: proc(text, name: string) -> bool {
	if len(text) < len(name) {return false}
	for b, i in transmute([]u8)name {
		v := text[i]
		if v >= 'A' && v <= 'Z' {v += 'a' - 'A'}
		if v != u8(b) {return false}
	}
	return true
}
details_byte_is :: proc(text: string, i: int, b: u8) -> bool {return i < len(text) && text[i] == b}
details_is_alpha :: proc(b: u8) -> bool {return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'}
details_is_alnum :: proc(b: u8) -> bool {return details_is_alpha(b) || b >= '0' && b <= '9'}
details_tag_boundary :: proc(text: string, i: int) -> bool {return(
		i >= len(text) ||
		!details_is_alnum(text[i]) \
	)}
details_attr_continue :: proc(b: u8) -> bool {return(
		details_is_alnum(b) ||
		b == '-' ||
		b == '_' ||
		b == ':' \
	)}
details_skip_ws :: proc(text: string, from: int) -> int {
	i := from
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {details_charge(1); i += 1}
	return i
}
details_only_ws :: proc(text: string) -> bool {
	for b in transmute([]u8)text {if b != ' ' && b != '\t' {return false}}
	return true
}
details_trim_line :: proc(line: string) -> (string, int) {
	start, end := 0, len(line)
	for start < end && (line[start] == ' ' || line[start] == '\t') {start += 1}
	for end > start && (line[end - 1] == ' ' || line[end - 1] == '\t') {end -= 1}
	return line[start:end], start
}
details_trim_leading :: proc(line: string) -> (string, int) {
	start := 0
	for start < len(line) && (line[start] == ' ' || line[start] == '\t') {start += 1}
	return line[start:len(line)], start
}
summary_inner_is_empty :: proc(inner: string) -> bool {
	for b in inner {if b != ' ' && b != '\t' && b != '\n' && b != '\r' {return false}}
	return true
}
