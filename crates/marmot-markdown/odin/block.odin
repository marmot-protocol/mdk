package markdown


MAX_TABLE_COLUMNS :: 128

ContainerTag :: enum {
	Quote,
	List,
	Item,
	Details,
}
BlockSummaryState :: enum {
	Awaiting,
	Collecting,
	Done,
}
BlockContainerList :: struct {
	kind:              ListKind,
	tight, last_blank: bool,
	items:             [dynamic]ListItem,
}
BlockContainerDetails :: struct {
	open:             bool,
	opener_raw:       string,
	summary_inner:    string,
	summary_raw:      []string,
	summary_replayed: bool,
	pre_summary_gap:  u8,
	summary_state:    BlockSummaryState,
	collector:        SummaryCollector,
	collecting_raw:   [dynamic]string,
	failed:           bool,
}
BlockContainerData :: struct #raw_union {
	using list:    BlockContainerList,
	indent:        int,
	using details: BlockContainerDetails,
}
BlockContainer :: struct {
	tag:        ContainerTag,
	children:   [dynamic]Block,
	gaps:       [dynamic]u8,
	leading:    u8,
	// Only List, Item, and Details use their corresponding state.
	using data: BlockContainerData,
}
BlockLeafTag :: enum {
	Paragraph,
	Indented,
	Fenced,
	Math,
	Table,
}
BlockLeafIndented :: struct {
	pending_blanks: int,
	pending_gaps:   [MAX_CONTAINER_DEPTH + 1]u8,
	pending_lists:  [MAX_CONTAINER_DEPTH]bool,
}
BlockLeafVerbatim :: struct {
	fence:             u8,
	fence_len, indent: int,
	info:              string,
}
BlockLeafTable :: struct {
	alignments: []Alignment,
	header:     []string,
	rows:       [dynamic][]string,
}
BlockLeafData :: struct #raw_union {
	initial_text:   string,
	using verbatim: BlockLeafVerbatim,
	using table:    BlockLeafTable,
}
BlockLeaf :: struct {
	tag:        BlockLeafTag,
	content:    [dynamic]u8,
	// Paragraph, Fenced/Math, and Table states are disjoint.
	using data: BlockLeafData,
}
BlockParser :: struct {
	refs:                                    RefMap,
	root:                                    [dynamic]Block,
	root_gaps:                               [dynamic]u8,
	containers:                              [dynamic]BlockContainer,
	leaf:                                    ^BlockLeaf,
	leaf_storage:                            BlockLeaf,
	indented:                                BlockLeafIndented,
	leaf_gap:                                u8,
	pending_gaps:                            [MAX_CONTAINER_DEPTH + 1]u8,
	details_window, depth_limit, line_start: int,
}
BlockCursor :: struct {
	col, off: int,
}
BlockMatch :: struct {
	cursor:       BlockCursor,
	depth:        int,
	blank_owners: [MAX_CONTAINER_DEPTH + 1]bool,
}
BlockListMarker :: struct {
	kind:                         ListKind,
	indent, col_after, off_after: int,
}

parse_blocks :: proc(input: string) -> (Document, RefMap) {
	details_work_reset()
	p := bp_new(details_window(input))
	start := 0
	for byte, i in transmute([]u8)input {
		if i < start || byte != '\n' && byte != '\r' {continue}
		bp_feed(&p, input[start:i], start)
		start = i + 1
		if byte == '\r' && start < len(input) && input[start] == '\n' {start += 1}
	}
	if start < len(input) {bp_feed(&p, input[start:len(input)], start)}
	bp_close_to(&p, 0)
	return Document{p.root[:], p.root_gaps[:]}, p.refs
}

bp_new :: proc(window: int) -> BlockParser {
	return BlockParser{details_window = window, depth_limit = MAX_CONTAINER_DEPTH}
}
bp_leaf_is :: proc(p: ^BlockParser, tag: BlockLeafTag) -> bool {
	return p.leaf != nil && p.leaf.tag == tag
}
bp_start_leaf :: proc(p: ^BlockParser, tag: BlockLeafTag) {
	p.leaf_gap = bp_take_gap(p)
	// Reset descriptors, not their backing storage: closed blocks retain that data.
	p.leaf_storage = BlockLeaf {
		tag = tag,
	}
	p.leaf = &p.leaf_storage
	if tag == .Indented {p.indented = {}}
}
bp_leaf_text :: proc(leaf: ^BlockLeaf) -> string {
	if len(leaf.content) == 0 {return leaf.initial_text}
	return string(leaf.content[:])
}
bp_text :: proc(text: string) -> []Inline {
	inlines := make([]Inline, 1)
	inlines[0] = Inline {
		tag  = .Text,
		text = text,
	}
	return inlines
}
bp_top :: proc(p: ^BlockParser) -> ^BlockContainer {
	if len(p.containers) == 0 {return nil}
	return &p.containers[len(p.containers) - 1]
}
bp_pop :: proc(p: ^BlockParser) -> BlockContainer {
	c := p.containers[len(p.containers) - 1]
	resize(&p.containers, len(p.containers) - 1)
	return c
}
bp_inc_gap :: proc(gap: ^u8) {gap^ = min(gap^ + 1, u8(MAX_SOURCE_BLANK_LINES))}

bp_feed :: proc(p: ^BlockParser, line: string, line_start: int) {
	p.line_start = line_start
	matched := bp_match(p, line)
	cursor := matched.cursor
	blank := is_blank(line[cursor.off:len(line)])
	verbatim := bp_leaf_is(p, .Fenced) || bp_leaf_is(p, .Math)
	if blank {
		mark_blank := true
		if bp_leaf_is(p, .Indented) {
			p.indented.pending_blanks += 1
			bp_record_blank(
				&p.indented.pending_gaps,
				p.containers[:],
				is_blank(line),
				&matched.blank_owners,
			)
			bp_record_list(&p.indented.pending_lists, p.containers[:], matched.depth)
			mark_blank = false
		} else if verbatim {
			push(&p.leaf.content, '\n')
			mark_blank = false
		} else {bp_close_leaf(p)}
		if mark_blank {
			bp_flush_summary(p)
			bp_record_blank(
				&p.pending_gaps,
				p.containers[:],
				is_blank(line),
				&matched.blank_owners,
			)
			bp_mark_list_blank(p, matched.depth)
		}
		return
	}
	if matched.depth < len(p.containers) {
		if bp_leaf_is(p, .Paragraph) && bp_lazy(p, line, cursor, matched.depth) {
			bp_append_from(p, line, cursor.off)
			return
		}
		bp_close_to(p, matched.depth)
	}
	if verbatim && p.leaf != nil {bp_verbatim(p, line, cursor); return}
	if bp_leaf_is(p, .Table) {
		rest := line[cursor.off:len(line)]
		if text_contains(rest, "|") {
			cells := split_table_row(rest)
			row := make([]string, len(p.leaf.header))
			copy(row, cells)
			push(&p.leaf.rows, row)
			return
		}
		bp_close_leaf(p)
	}
	col, off := cursor.col, cursor.off
	for {
		sub_col, sub_off := measure_indent(line[off:len(line)])
		probe_col, probe_off := col + sub_col, off + sub_off
		if sub_col < 4 {
			rest := line[probe_off:len(line)]
			if len(rest) != 0 {
				if bp_close_details(p, rest, probe_off) {return}
				if bp_accept_summary(p, rest, probe_off) {return}
				if bp_open_details(p, rest, probe_off) {return}
				if level, text, ok := parse_atx_heading(rest); ok {
					bp_close_leaf(p)
					bp_push_new(p, Block{tag = .Heading, level = level, inlines = bp_text(text)})
					return
				}
				if fence, count, info, ok := parse_fence_open(rest); ok {
					bp_close_leaf(p); bp_start_leaf(p, .Fenced)
					p.leaf.fence, p.leaf.fence_len, p.leaf.info, p.leaf.indent =
						fence, count, info, sub_col
					return
				}
				if is_math_fence(rest) {
					bp_close_leaf(p); bp_start_leaf(p, .Math); p.leaf.indent = sub_col
					return
				}
				if bp_leaf_is(p, .Paragraph) {
					if level, ok := parse_setext_underline(rest); ok {
						raw := bp_harvest_refs(p, bp_leaf_text(p.leaf))
						p.leaf = nil
						if len(raw) == 0 {p.leaf_gap = 0} else {
							gap := p.leaf_gap; p.leaf_gap = 0
							bp_push(
								p,
								Block{tag = .Heading, level = level, inlines = bp_text(raw)},
								gap,
							)
							return
						}
					}
				}
				if is_thematic_break(
					rest,
				) {bp_close_leaf(p); bp_push_new(p, Block{tag = .ThematicBreak}); return}
				if bp_promote_table(p, rest) {return}
				if rest[0] == '>' {
					if nc, no, ok := try_open_blockquote(line, probe_col, probe_off); ok {
						if len(p.containers) >=
						   p.depth_limit {bp_append_from(p, line, probe_off); return}
						bp_close_leaf(p)
						leading := bp_take_gap(p)
						push(&p.containers, BlockContainer{tag = .Quote, leading = leading})
						col, off = nc, no
						if is_blank(
							line[off:len(line)],
						) {bp_inc_gap(&p.pending_gaps[len(p.containers)]); return}
						continue
					}
				}
				if marker, ok := try_open_list_marker(
					line,
					probe_col,
					probe_off,
					bp_leaf_is(p, .Paragraph),
				); ok {
					if len(p.containers) + 2 >
					   p.depth_limit {bp_append_from(p, line, probe_off); return}
					bp_close_leaf(p)
					if !bp_ensure_list(p, marker.kind) {p.pending_gaps = {}}
					push(&p.containers, BlockContainer{tag = .Item, indent = marker.indent})
					col, off = marker.col_after, marker.off_after
					if off >= len(line) {return}
					continue
				}
			}
		}
		if sub_col >= 4 && !bp_leaf_is(p, .Paragraph) {
			if bp_collecting(p) && bp_accept_summary(p, line[off:len(line)], off) {return}
			bp_end_summary(p)
			stripped := indented_strip(line, off)
			if bp_leaf_is(p, .Indented) {
				for _ in 0 ..< p.indented.pending_blanks {push(&p.leaf.content, '\n')}
				p.indented = {}
			} else {bp_close_leaf(p); bp_start_leaf(p, .Indented)}
			push(&p.leaf.content, ..transmute([]u8)stripped)
			push(&p.leaf.content, '\n')
			return
		}
		bp_append_from(p, line, off)
		return
	}
}

bp_match :: proc(p: ^BlockParser, line: string) -> BlockMatch {
	m := BlockMatch{}
	// A suffix is blank exactly when it starts after the last nonblank byte.
	content_end := len(line)
	for content_end > 0 && (line[content_end - 1] == ' ' || line[content_end - 1] == '\t') {
		content_end -= 1
	}
	col, off := 0, 0
	for &c, i in p.containers {
		switch c.tag {
		case .Quote:
			sub_col, sub_off := measure_indent(line[off:len(line)])
			probe := off + sub_off
			if sub_col >= 4 || probe >= len(line) || line[probe] != '>' {
				m.cursor, m.depth = BlockCursor{col, off}, i; return m
			}
			col += sub_col + 1; off = probe + 1
			if off < len(line) {
				if line[off] ==
				   ' ' {col += 1; off += 1} else if line[off] == '\t' {col += 4 - col % 4; off += 1}
			}
			m.blank_owners[i + 1] = off >= content_end
		case .List, .Details:
		case .Item:
			if col >= c.indent {m.blank_owners[i + 1] = off >= content_end; continue}
			if off >= content_end {
				m.blank_owners[i + 1] =
					true; m.cursor, m.depth = BlockCursor{col, off}, i + 1; return m
			}
			nc, consumed := consume_cols(line[off:len(line)], col, c.indent)
			if nc < c.indent {m.cursor, m.depth = BlockCursor{col, off}, i; return m}
			col = nc; off += consumed; m.blank_owners[i + 1] = off >= content_end
		}
	}
	m.cursor, m.depth = BlockCursor{col, off}, len(p.containers)
	return m
}

bp_verbatim :: proc(p: ^BlockParser, line: string, cursor: BlockCursor) {
	rest := line[cursor.off:len(line)]
	close := false
	if p.leaf.tag ==
	   .Fenced {close = is_close_fence(rest, p.leaf.fence, p.leaf.fence_len)} else {close = is_math_close(rest)}
	if close {bp_close_leaf(p); return}
	stripped := strip_n_leading_spaces(rest, p.leaf.indent)
	push(&p.leaf.content, ..transmute([]u8)stripped)
	push(&p.leaf.content, '\n')
}
bp_append_from :: proc(p: ^BlockParser, line: string, off: int) {
	rest := ""
	if off <= len(line) {rest = line[off:len(line)]}
	i := skip_inline_ws(rest, 0)
	bp_append_para(p, rest[i:len(rest)])
}
bp_promote_table :: proc(p: ^BlockParser, line: string) -> bool {
	if !bp_leaf_is(p, .Paragraph) {return false}
	prev := bp_leaf_text(p.leaf)
	if text_contains(prev, "\n") {return false}
	alignments, ok := parse_table_delim_row(line)
	if !ok {return false}
	header := split_table_row(prev)
	if len(header) != len(alignments) {return false}
	p.leaf.tag = .Table; p.leaf.alignments = alignments; p.leaf.header = header
	p.leaf.rows = nil
	return true
}
bp_append_para :: proc(p: ^BlockParser, text: string) {
	bp_consume_blank(p)
	if bp_promote_table(p, text) {return}
	if !bp_leaf_is(p, .Paragraph) {
		bp_close_leaf(p); bp_start_leaf(p, .Paragraph)
		p.leaf.initial_text = text
		return
	}
	if len(p.leaf.content) == 0 {
		push(&p.leaf.content, ..transmute([]u8)p.leaf.initial_text)
	}
	push(&p.leaf.content, '\n')
	push(&p.leaf.content, ..transmute([]u8)text)
}
bp_close_leaf :: proc(p: ^BlockParser) {
	if p.leaf == nil {return}
	// Callbacks may start another leaf, overwriting the parser-owned descriptors.
	leaf := p.leaf^
	p.leaf = nil
	gap := p.leaf_gap; p.leaf_gap = 0
	switch leaf.tag {
	case .Paragraph:
		raw := bp_harvest_refs(p, bp_leaf_text(&leaf))
		if len(raw) != 0 {bp_push(p, Block{tag = .Paragraph, inlines = bp_text(raw)}, gap)}
	case .Indented:
		// Only indented code copies these arrays; replay must not overwrite them
		// before the pending blanks are applied after bp_push.
		pending := p.indented
		bp_push(
			p,
			Block {
				tag = .CodeBlock,
				code_kind = .Indented,
				code = {content = string(leaf.content[:])},
			},
			gap,
		)
		for gap, i in pending.pending_gaps {p.pending_gaps[i] = min(p.pending_gaps[i] + gap, u8(MAX_SOURCE_BLANK_LINES))}
		for &c, i in p.containers {if pending.pending_lists[i] && c.tag == .List {c.last_blank = true}}
	case .Fenced:
		bp_push(
			p,
			Block {
				tag = .CodeBlock,
				code_kind = .Fenced,
				code = {info = leaf.info, content = string(leaf.content[:])},
			},
			gap,
		)
	case .Math:
		bp_push(p, Block{tag = .MathBlock, math = string(leaf.content[:])}, gap)
	case .Table:
		header := make([]TableCell, len(leaf.header))
		for s, i in leaf.header {header[i].inlines = bp_text(s)}
		rows := make([][]TableCell, len(leaf.rows))
		for row, i in leaf.rows {
			rows[i] = make([]TableCell, len(row))
			for s, j in row {rows[i][j].inlines = bp_text(s)}
		}
		bp_push(
			p,
			Block {
				tag = .Table,
				table = {alignments = leaf.alignments, header = header, rows = rows},
			},
			gap,
		)
	}
}

bp_record_blank :: proc(
	gaps: ^[MAX_CONTAINER_DEPTH + 1]u8,
	containers: []BlockContainer,
	physical: bool,
	owners: ^[MAX_CONTAINER_DEPTH + 1]bool,
) {
	if physical {
		inner_from := 0
		for &c, i in containers {if c.tag == .Details {inner_from = i + 1}}
		if inner_from == 0 {bp_inc_gap(&gaps[0])}
		for &c, i in containers {
			if i + 1 < inner_from {continue}
			if c.tag != .List {bp_inc_gap(&gaps[i + 1])}
		}
	} else {for owner, i in owners^ {if owner {bp_inc_gap(&gaps[i])}}}
}
bp_record_list :: proc(
	pending: ^[MAX_CONTAINER_DEPTH]bool,
	containers: []BlockContainer,
	depth: int,
) {
	for i := min(depth, len(containers)) - 1; i >= 0; i -= 1 {
		if containers[i].tag == .List {pending[i] = true; return}
	}
}
bp_mark_list_blank :: proc(p: ^BlockParser, depth: int) {
	for i := min(depth, len(p.containers)) - 1; i >= 0; i -= 1 {
		if p.containers[i].tag == .List {p.containers[i].last_blank = true; return}
	}
}
bp_consume_blank :: proc(p: ^BlockParser) {
	for &c in p.containers {
		if c.tag == .List && c.last_blank {c.tight = false; c.last_blank = false}
	}
}
bp_take_gap :: proc(p: ^BlockParser) -> u8 {
	bp_consume_blank(p); bp_close_lists(p)
	gap := p.pending_gaps[len(p.containers)]
	p.pending_gaps = {}
	return gap
}
bp_close_lists :: proc(p: ^BlockParser) {
	for c := bp_top(p);
	    c != nil && c.tag == .List;
	    c = bp_top(p) {closed := bp_pop(p); bp_close_container(p, &closed)}
}
bp_push_new :: proc(p: ^BlockParser, block: Block) {gap := bp_take_gap(p); bp_push(p, block, gap)}
bp_push :: proc(p: ^BlockParser, block: Block, gap: u8) {
	bp_consume_blank(p); bp_close_lists(p)
	if c := bp_top(p);
	   c !=
	   nil {push(&c.children, block); push(&c.gaps, gap)} else {push(&p.root, block); push(&p.root_gaps, gap)}
}
bp_close_to :: proc(p: ^BlockParser, depth: int) {
	bp_close_leaf(p)
	for len(p.containers) > depth {closed := bp_pop(p); bp_close_container(p, &closed)}
}
bp_close_container :: proc(p: ^BlockParser, c: ^BlockContainer) {
	switch c.tag {
	case .Quote:
		bp_push(
			p,
			Block {
				tag = .BlockQuote,
				quote = {blocks = c.children[:], blank_lines_before = c.gaps[:]},
			},
			c.leading,
		)
	case .Item:
		checked := detect_task_marker(c.children[:])
		if list := bp_top(p);
		   list != nil &&
		   list.tag == .List {push(&list.items, ListItem{c.children[:], c.gaps[:], checked})}
	case .List:
		bp_push(
			p,
			Block{tag = .List, list = {kind = c.kind, tight = c.tight, items = c.items[:]}},
			c.leading,
		)
	case .Details:
		bp_finish_details(p, c, "", 0, false)
	}
}
bp_ensure_list :: proc(p: ^BlockParser, kind: ListKind) -> bool {
	if c := bp_top(p); c != nil && c.tag == .List {
		if lists_compatible(c.kind, kind) {return false}
		bp_close_to(p, len(p.containers) - 1)
	}
	leading := bp_take_gap(p)
	push(&p.containers, BlockContainer{tag = .List, kind = kind, tight = true, leading = leading})
	return true
}

bp_details_parent :: proc(p: ^BlockParser) -> bool {
	n := len(p.containers)
	if n == 0 {return false}
	if p.containers[n - 1].tag == .Details {return true}
	return p.containers[n - 1].tag == .List && n > 1 && p.containers[n - 2].tag == .Details
}
bp_collecting :: proc(p: ^BlockParser) -> bool {
	c := bp_top(p)
	return c != nil && c.tag == .Details && c.summary_state == .Collecting
}
bp_end_summary :: proc(p: ^BlockParser) {
	if c := bp_top(p);
	   c != nil && c.tag == .Details && c.summary_state == .Awaiting {c.summary_state = .Done}
}
bp_details_gap :: proc(p: ^BlockParser) -> u8 {
	if c := bp_top(p); c != nil && c.tag == .Details {return p.pending_gaps[len(p.containers)]}
	return 0
}
bp_details_pre_gap :: proc(p: ^BlockParser) -> u8 {
	if c := bp_top(p); c != nil && c.tag == .Details {
		if c.pre_summary_gap > 0 {return c.pre_summary_gap}
		return bp_details_gap(p)
	}
	return 0
}
bp_clear_details_gap :: proc(p: ^BlockParser) {
	if c := bp_top(p); c != nil && c.tag == .Details {p.pending_gaps[len(p.containers)] = 0}
}
bp_take_summary_raw :: proc(p: ^BlockParser) -> []string {
	if bp_collecting(p) {
		c := bp_top(p)
		raw := c.collecting_raw[:]
		c.collecting_raw = nil
		return raw
	}
	return nil
}
bp_summary_complete :: proc(p: ^BlockParser, inner: string, raw, leftover: []string) {
	summary_lines, leftover_raw := raw, leftover
	if len(leftover) > 0 && len(leftover) <= len(raw) {
		split := len(raw) - len(leftover)
		summary_lines, leftover_raw = raw[:split], raw[split:]
	}
	gap := bp_details_gap(p)
	if c := bp_top(p); c != nil && c.tag == .Details {
		c.summary_inner = inner
		if summary_inner_is_empty(inner) {c.summary_inner = ""}
		c.summary_raw, c.pre_summary_gap, c.summary_state = summary_lines, gap, .Done
	}
	bp_clear_details_gap(p)
	if len(leftover_raw) > 0 {bp_replay(p, leftover_raw, 0)}
}
bp_summary_fail :: proc(p: ^BlockParser, raw: []string, consume: bool) -> bool {
	gap := bp_details_pre_gap(p)
	if c := bp_top(p); c != nil && c.tag == .Details {
		c.failed, c.summary_state, c.summary_replayed = true, .Done, true
	}
	bp_replay(p, raw, gap)
	return consume
}
bp_close_details :: proc(p: ^BlockParser, rest: string, probe_off: int) -> bool {
	close, ok := parse_details_closer_line(rest)
	if !ok || !bp_details_parent(p) {return false}
	if bp_collecting(p) {
		c := bp_top(p)
		if summary_has_unmatched(&c.collector) {return false}
		if inner, leftover, done := summary_finalize(&c.collector); done {
			raw := bp_take_summary_raw(p)
			bp_summary_complete(p, inner, raw, leftover)
		}
	}
	bp_close_leaf(p); bp_close_lists(p)
	end := p.line_start + probe_off + close.tag_end
	if c := bp_top(p); c != nil && c.tag == .Details {
		closed := bp_pop(p)
		bp_finish_details(p, &closed, trim_ascii_ws(rest), end, true)
		return true
	}
	return false
}
bp_open_details :: proc(p: ^BlockParser, rest: string, probe_off: int) -> bool {
	start := p.line_start + probe_off
	if start >= p.details_window {return false}
	open, ok := parse_details_opener_line(rest)
	if !ok ||
	   start + open.tag_end > p.details_window ||
	   len(p.containers) >= p.depth_limit {return false}
	bp_close_leaf(p)
	leading := bp_take_gap(p)
	push(
		&p.containers,
		BlockContainer {
			tag = .Details,
			open = open.open,
			opener_raw = trim_ascii_ws(rest),
			leading = leading,
		},
	)
	return true
}
bp_accept_summary :: proc(p: ^BlockParser, rest: string, probe_off: int) -> bool {
	budget := max(p.details_window - p.line_start - probe_off, 0)
	extends_past := p.line_start + probe_off + len(rest) > p.details_window
	c := bp_top(p)
	if c == nil || c.tag != .Details || c.summary_state == .Done {return false}
	if budget == 0 {
		if c.summary_state == .Awaiting {bp_end_summary(p); return false}
		return bp_summary_fail(p, bp_take_summary_raw(p), false)
	}
	if c.summary_state == .Collecting {
		if extends_past {return bp_summary_fail(p, bp_take_summary_raw(p), false)}
		outcome := summary_push_line(&c.collector, rest, budget)
		push(&c.collecting_raw, rest)
		switch outcome.kind {
		case .Complete:
			bp_summary_complete(p, outcome.inner, bp_take_summary_raw(p), nil); return true
		case .StillOpen:
			return true
		case .Malformed:
			return bp_summary_fail(p, bp_take_summary_raw(p), true)
		}
	}
	line := parse_summary_line_bounded(rest, budget)
	switch line.kind {
	case .NotSummary:
		c.summary_state = .Done; return false
	case .Complete:
		raw := make([]string, 1); raw[0] = rest
		bp_summary_complete(p, line.inner, raw, nil)
		return true
	case .OpenOnly:
		if !extends_past {
			gap := bp_details_gap(p)
			c.collector = summary_collector_from(line.after_open)
			c.summary_state, c.pre_summary_gap = .Collecting, gap
			push(&c.collecting_raw, rest)
			bp_clear_details_gap(p)
			return true
		}
		c.failed, c.summary_state = true, .Done
		return false
	case .Malformed:
		c.failed, c.summary_state = true, .Done; return false
	}
	return false
}
bp_flush_summary :: proc(p: ^BlockParser) {
	if !bp_collecting(p) {return}
	c := bp_top(p)
	if inner, leftover, ok := summary_finalize(&c.collector); ok {
		bp_summary_complete(p, inner, bp_take_summary_raw(p), leftover)
		return
	}
	bp_summary_fail(p, c.collecting_raw[:], true)
}
bp_finish_details :: proc(
	p: ^BlockParser,
	c: ^BlockContainer,
	closer: string,
	end: int,
	has_closer: bool,
) {
	collecting := c.summary_state == .Collecting
	raw := c.summary_raw
	if collecting {raw = c.collecting_raw[:]}
	matched := !c.failed && !collecting && has_closer && end <= p.details_window
	if !matched {
		children, gaps := c.children, c.gaps
		if !c.summary_replayed && len(raw) > 0 {
			restored, restored_gaps := bp_parse_ordinary(p, raw, c.pre_summary_gap)
			bp_push(p, Block{tag = .Paragraph, inlines = bp_text(c.opener_raw)}, c.leading)
			for block, i in restored {bp_push(p, block, restored_gaps[i])}
		} else {
			bp_push(p, Block{tag = .Paragraph, inlines = bp_text(c.opener_raw)}, c.leading)
		}
		for block, i in children {bp_push(p, block, gaps[i])}
		if has_closer {bp_push(p, Block{tag = .Paragraph, inlines = bp_text(closer)}, 0)}
		return
	}
	summary: []Inline
	if len(c.summary_inner) > 0 {summary = bp_text(c.summary_inner)}
	bp_push(
		p,
		Block {
			tag = .Details,
			details = {
				summary = summary,
				open = c.open,
				body = c.children[:],
				blank_lines_before = c.gaps[:],
			},
		},
		c.leading,
	)
}
bp_parse_ordinary :: proc(p: ^BlockParser, lines: []string, first_gap: u8) -> ([]Block, []u8) {
	replay := BlockParser {
		refs        = p.refs,
		depth_limit = max(p.depth_limit - len(p.containers), 0),
	}
	replay.pending_gaps[0] = first_gap
	for line in lines {bp_feed(&replay, line, 0)}
	bp_close_to(&replay, 0)
	p.refs = replay.refs
	return replay.root[:], replay.root_gaps[:]
}
bp_replay :: proc(p: ^BlockParser, lines: []string, first_gap: u8) {
	blocks, gaps := bp_parse_ordinary(p, lines, first_gap)
	for block, i in blocks {bp_push(p, block, gaps[i])}
}

try_open_blockquote :: proc(line: string, col, off: int) -> (int, int, bool) {
	sub_col, sub_off := measure_indent(line[off:len(line)])
	probe := off + sub_off
	if sub_col >= 4 || probe >= len(line) || line[probe] != '>' {return 0, 0, false}
	nc, no := col + sub_col + 1, probe + 1
	if no < len(line) {
		if line[no] == ' ' {nc += 1; no += 1} else if line[no] == '\t' {nc += 4 - nc % 4; no += 1}
	}
	return nc, no, true
}
try_open_list_marker :: proc(
	line: string,
	col, off: int,
	interrupting: bool,
) -> (
	BlockListMarker,
	bool,
) {
	sub_col, sub_off := measure_indent(line[off:len(line)])
	if sub_col >= 4 {return {}, false}
	marker_off, marker_col := off + sub_off, col + sub_col
	if marker_off >= len(line) {return {}, false}
	kind: ListKind
	marker_end := marker_off
	b := line[marker_off]
	if b == '-' || b == '+' || b == '*' {
		kind = ListKind {
			tag    = .Bullet,
			marker = b,
		}; marker_end += 1
	} else if b >= '0' && b <= '9' {
		i := marker_off
		start: u32
		for i < len(line) &&
		    line[i] >= '0' &&
		    line[i] <= '9' &&
		    i - marker_off < 9 {start = start * 10 + u32(line[i] - '0'); i += 1}
		if i >= len(line) ||
		   (line[i] != '.' && line[i] != ')') ||
		   (interrupting && start != 1) {return {}, false}
		kind = ListKind {
			tag       = .Ordered,
			start     = start,
			delimiter = line[i],
		}; marker_end = i + 1
	} else {return {}, false}
	if marker_end < len(line) &&
	   line[marker_end] != ' ' &&
	   line[marker_end] != '\t' {return {}, false}
	if interrupting &&
	   (marker_end >= len(line) || is_blank(line[marker_end:len(line)])) {return {}, false}
	after_marker := marker_col + marker_end - marker_off
	ws_col, ws_off := measure_indent(line[marker_end:len(line)])
	nc, no := 0, 0
	if marker_end >= len(line) ||
	   is_blank(
		   line[marker_end:len(line)],
	   ) {nc, no = after_marker + 1, len(line)} else if ws_col >= 5 {
		nc, no = after_marker + 1, marker_end + 1
	} else {nc, no = after_marker + ws_col, marker_end + ws_off}
	return BlockListMarker{kind, nc, nc, no}, true
}
lists_compatible :: proc(a, b: ListKind) -> bool {
	if a.tag != b.tag {return false}
	if a.tag == .Bullet {return a.marker == b.marker}
	return a.delimiter == b.delimiter
}
bp_lazy :: proc(p: ^BlockParser, line: string, cursor: BlockCursor, depth: int) -> bool {
	col, off := measure_indent(line[cursor.off:len(line)])
	if col >= 4 {return true}
	probe_col, probe_off := cursor.col + col, cursor.off + off
	rest := line[probe_off:len(line)]
	if len(rest) == 0 {return false}
	if _, _, ok := parse_atx_heading(rest); ok {return false}
	if is_thematic_break(rest) || rest[0] == '>' {return false}
	if _, _, _, ok := parse_fence_open(rest); ok {return false}
	if is_math_fence(rest) {return false}
	if _, ok := try_open_list_marker(line, cursor.col, cursor.off, true); ok {return false}
	if _, ok := parse_details_opener_line(rest); ok {return false}
	if _, ok := parse_details_closer_line(rest); ok {return false}
	if open, ok := try_open_list_marker(line, probe_col, probe_off, false); ok {
		for i := min(depth, len(p.containers)) - 1; i >= 0; i -= 1 {
			if p.containers[i].tag ==
			   .List {return !lists_compatible(p.containers[i].kind, open.kind)}
		}
	}
	return true
}
detect_task_marker :: proc(children: []Block) -> i32 {
	if len(children) == 0 ||
	   children[0].tag != .Paragraph ||
	   len(children[0].inlines) == 0 ||
	   children[0].inlines[0].tag != .Text {return -1}
	text := children[0].inlines[0].text
	if len(text) >= 4 && text[0] == '[' && text[2] == ']' && text[3] == ' ' {
		checked: i32 = -1
		if text[1] == ' ' {checked = 0} else if text[1] == 'x' || text[1] == 'X' {checked = 1}
		if checked >= 0 {children[0].inlines[0].text = text[4:len(text)]; return checked}
	}
	return -1
}
consume_cols :: proc(line: string, start_col, target: int) -> (int, int) {
	col, off := start_col, 0
	for col < target && off < len(line) {
		if line[off] == ' ' {col += 1} else if line[off] == '\t' {col += 4 - col % 4} else {break}
		off += 1
	}
	return col, off
}
trim_ascii_ws :: proc(s: string) -> string {
	lo, hi := 0, len(s)
	for lo < hi && (s[lo] == ' ' || s[lo] == '\t') {lo += 1}
	for hi > lo && (s[hi - 1] == ' ' || s[hi - 1] == '\t') {hi -= 1}
	return s[lo:hi]
}
parse_atx_heading :: proc(s: string) -> (u8, string, bool) {
	if len(s) == 0 || s[0] != '#' {return 0, "", false}
	n := 0
	for n < len(s) && s[n] == '#' {n += 1}
	if n > 6 || (n < len(s) && s[n] != ' ' && s[n] != '\t') {return 0, "", false}
	core := trim_ascii_ws(s[n:len(s)])
	i := len(core)
	for i > 0 && core[i - 1] == '#' {i -= 1}
	if i < len(core) {
		if i ==
		   0 {core = ""} else if core[i - 1] == ' ' || core[i - 1] == '\t' {core = trim_ascii_ws(core[:i])}
	}
	return u8(n), core, true
}
parse_setext_underline :: proc(s: string) -> (u8, bool) {
	if len(s) == 0 || (s[0] != '=' && s[0] != '-') {return 0, false}
	i := 0
	for i < len(s) && s[i] == s[0] {i += 1}
	if !is_blank(s[i:len(s)]) {return 0, false}
	if s[0] == '=' {return 1, true}
	return 2, true
}
parse_fence_open :: proc(s: string) -> (u8, int, string, bool) {
	if len(s) == 0 || (s[0] != '`' && s[0] != '~') {return 0, 0, "", false}
	i := 0
	for i < len(s) && s[i] == s[0] {i += 1}
	if i < 3 || (s[0] == '`' && text_contains(s[i:len(s)], "`")) {return 0, 0, "", false}
	info := trim_ascii_ws(s[i:len(s)])
	first_control := len(info)
	for r, pos in info {
		if helpers_is_control(r) {first_control = pos; break}
	}
	if first_control == len(info) {return s[0], i, info, true}
	out: [dynamic]u8
	push(&out, ..transmute([]u8)info[0:first_control])
	for r, pos in info[first_control:len(info)] {
		if !helpers_is_control(r) {
			n := 1
			if r >= 0x10000 {n = 4} else if r >= 0x800 {n = 3} else if r >= 0x80 {n = 2}
			start := first_control + pos
			push(&out, ..transmute([]u8)info[start:start + n])
		}
	}
	return s[0], i, string(out[:]), true
}
is_close_fence :: proc(s: string, fence: u8, count: int) -> bool {
	col, off := measure_indent(s)
	if col >= 4 {return false}
	i := off
	for i < len(s) && s[i] == fence {i += 1}
	return i - off >= count && is_blank(s[i:len(s)])
}
is_math_fence :: proc(s: string) -> bool {return(
		len(s) >= 2 &&
		s[0] == '$' &&
		s[1] == '$' &&
		(len(s) == 2 || s[2] != '$') &&
		is_blank(s[2:len(s)]) \
	)}
is_math_close :: proc(s: string) -> bool {col, off := measure_indent(s); return(
		col < 4 &&
		is_math_fence(s[off:len(s)]) \
	)}
indented_strip :: proc(line: string, off: int) -> string {_, consumed := consume_cols(
		line[off:len(line)],
		0,
		4,
	)
	return line[off + consumed:len(line)]}
strip_n_leading_spaces :: proc(s: string, n: int) -> string {
	i := 0
	for i < n && i < len(s) && s[i] == ' ' {i += 1}
	return s[i:len(s)]
}
parse_table_delim_row :: proc(line: string) -> ([]Alignment, bool) {
	if !text_contains(line, "|") && !text_contains(line, "-") {return nil, false}
	cells := split_table_row(line)
	if len(cells) == 0 || len(cells) > MAX_TABLE_COLUMNS {return nil, false}
	alignments := make([]Alignment, len(cells))
	for cell, i in cells {
		s := helpers_trim(cell)
		if len(s) == 0 {return nil, false}
		left, right := s[0] == ':', s[len(s) - 1] == ':'
		lo, hi := 0, len(s)
		if left {lo += 1}; if right {hi -= 1}
		if lo >= hi {return nil, false}
		for b in transmute([]u8)s[lo:hi] {if b != '-' {return nil, false}}
		if left &&
		   right {alignments[i] = .Center} else if left {alignments[i] = .Left} else if right {alignments[i] = .Right} else {alignments[i] = .None}
	}
	return alignments, true
}
split_table_row :: proc(line: string) -> []string {
	lo, hi := 0, len(line)
	for lo < hi && (line[lo] == ' ' || line[lo] == '\t') {lo += 1}
	for hi > lo && (line[hi - 1] == ' ' || line[hi - 1] == '\t') {hi -= 1}
	if lo < hi && line[lo] == '|' {lo += 1}
	if hi > lo && line[hi - 1] == '|' && (hi < 2 || line[hi - 2] != '\\') {hi -= 1}
	cells: [dynamic]string
	current: [dynamic]u8
	start, k := lo, lo
	for k < hi {
		b := line[k]
		if b == '\\' && k + 1 < hi && line[k + 1] == '|' {
			push(&current, ..transmute([]u8)line[start:k])
			push(&current, '|')
			k += 2; start = k; continue
		}
		if b == '|' {
			cell := line[start:k]
			if len(current) > 0 {
				push(&current, ..transmute([]u8)cell)
				cell = string(current[:])
			}
			push(&cells, helpers_trim(cell))
			current = nil; k += 1; start = k; continue
		}
		k += 1
	}
	cell := line[start:hi]
	if len(current) > 0 {
		push(&current, ..transmute([]u8)cell)
		cell = string(current[:])
	}
	push(&cells, helpers_trim(cell))
	return cells[:]
}
is_thematic_break :: proc(s: string) -> bool {
	if len(s) == 0 || (s[0] != '-' && s[0] != '*' && s[0] != '_') {return false}
	count := 0
	for b in transmute([]u8)s {
		if b == s[0] {count += 1} else if b != ' ' && b != '\t' {return false}
	}
	return count >= 3
}

bp_harvest_refs :: proc(p: ^BlockParser, raw: string) -> string {
	rest := raw
	for {
		label, def, consumed, ok := parse_one_ref_def(rest)
		if !ok {break}
		normalized := normalize_label(label)
		if len(normalized) > 0 {
			if _, exists := ref_map_get(p.refs, normalized);
			   !exists {ref_map_set(&p.refs, normalized, def)}
		}
		rest = rest[consumed:len(rest)]
		if len(rest) > 0 && rest[0] == '\n' {rest = rest[1:len(rest)]}
	}
	return rest
}
parse_one_ref_def :: proc(s: string) -> (string, LinkRef, int, bool) {
	i, col := 0, 0
	for col < 4 && i < len(s) && s[i] == ' ' {i += 1; col += 1}
	if col >= 4 || i >= len(s) || s[i] != '[' {return "", {}, 0, false}
	label_start := i + 1
	j := label_start
	for j < len(s) && s[j] != ']' {
		if s[j] == '\\' && j + 1 < len(s) {j += 2} else {j += 1}
		if j - label_start > 999 {return "", {}, 0, false}
	}
	if j >= len(s) || s[j] != ']' {return "", {}, 0, false}
	label := s[label_start:j]
	if len(helpers_trim(label)) == 0 {return "", {}, 0, false}
	i = j + 1
	if i >= len(s) || s[i] != ':' {return "", {}, 0, false}
	i = skip_ws_and_one_newline(s, i + 1)
	if i >= len(s) {return "", {}, 0, false}
	dest, ni, ok := parse_link_destination(s, i)
	if !ok {return "", {}, 0, false}
	i = ni
	after_dest := i
	ws := skip_inline_ws(s, after_dest)
	if ws < len(s) && s[ws] == '\n' {ws += 1}
	title_start := skip_inline_ws(s, ws)
	def := LinkRef {
		dest = dest,
	}
	end := i
	if title_start < len(s) &&
	   (s[title_start] == '"' || s[title_start] == '\'' || s[title_start] == '(') {
		if title, te, title_ok := parse_link_title(s, title_start); title_ok {
			after := skip_inline_ws(s, te)
			if after >= len(s) ||
			   s[after] == '\n' {def.title, def.has_title, end = title, true, after}
		}
	}
	if !def.has_title {
		after := skip_inline_ws(s, after_dest)
		if after < len(s) && s[after] != '\n' {return "", {}, 0, false}
		end = after
	}
	return label, def, end, true
}
skip_inline_ws :: proc(s: string, start: int) -> int {
	i := start
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {i += 1}
	return i
}
parse_link_destination :: proc(s: string, i: int) -> (string, int, bool) {
	if i >= len(s) {return "", 0, false}
	if s[i] == '<' {
		j := i + 1
		for j < len(s) && s[j] != '>' {
			b := s[j]
			if b == '<' || b < 0x20 || b == 0x7f {return "", 0, false}
			if b == '\\' && j + 1 < len(s) && is_ascii_punct(s[j + 1]) {j += 2; continue}
			j += 1
		}
		if j >= len(s) {return "", 0, false}
		return bp_decode_punctuation(s[i + 1:j]), j + 1, true
	}
	j, depth := i, 0
	for j < len(s) {
		b := s[j]
		if b == ' ' || b == '\t' || b == '\n' || b < 0x20 || b == 0x7f {break}
		if b == '\\' && j + 1 < len(s) && is_ascii_punct(s[j + 1]) {j += 2; continue}
		if b == '(' {depth += 1}
		if b == ')' {if depth == 0 {break}; depth -= 1}
		j += 1
	}
	if i == j || depth != 0 {return "", 0, false}
	return bp_decode_punctuation(s[i:j]), j, true
}
parse_link_title :: proc(s: string, i: int) -> (string, int, bool) {
	if i >= len(s) {return "", 0, false}
	open := s[i]
	close := open
	if open == '(' {close = ')'} else if open != '"' && open != '\'' {return "", 0, false}
	j := i + 1
	for j < len(s) {
		b := s[j]
		if b == '\\' && j + 1 < len(s) && is_ascii_punct(s[j + 1]) {j += 2; continue}
		if b == close {
			raw := s[i + 1:j]
			for r in raw {if helpers_is_control(r) {return "", 0, false}}
			return bp_decode_punctuation(raw), j + 1, true
		}
		if open == '(' && b == '(' {return "", 0, false}
		j += 1
	}
	return "", 0, false
}
// Validate destinations/titles before decoding: failed suffix probes must not
// retain a growing sequence of discarded buffers in the per-parse arena.
bp_decode_punctuation :: proc(raw: string) -> string {
	first := 0
	for first + 1 < len(raw) {
		if raw[first] == '\\' && is_ascii_punct(raw[first + 1]) {break}
		first += 1
	}
	if first + 1 >= len(raw) {return raw}
	out := make([dynamic]u8, 0, len(raw))
	push(&out, ..transmute([]u8)raw[:first])
	i := first
	for i < len(raw) {
		if raw[i] == '\\' && i + 1 < len(raw) && is_ascii_punct(raw[i + 1]) {i += 1}
		push(&out, raw[i])
		i += 1
	}
	return string(out[:])
}
normalize_label :: proc(label: string) -> string {
	lower := helpers_lowercase(label)
	out: [dynamic]u8
	prev_ws := true
	for i := 0; i < len(lower); i += 1 {
		b := lower[i]
		if b == ' ' || b == '\t' || b == '\n' {
			if !prev_ws {push(&out, ' '); prev_ws = true}
		} else {push(&out, b); prev_ws = false}
	}
	if len(out) > 0 && out[len(out) - 1] == ' ' {resize(&out, len(out) - 1)}
	return string(out[:])
}
