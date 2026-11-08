#+test
package markdown

import "core:testing"

details_test_join :: proc(parts: ..string) -> string {
	bytes: [dynamic]u8
	for part in parts {append(&bytes, ..transmute([]u8)part)}
	return string(bytes[:])
}
details_test_repeat :: proc(text: string, count: int) -> string {
	bytes := make([]u8, len(text) * count)
	for i in 0 ..< count {copy(bytes[i * len(text):], transmute([]u8)text)}
	return string(bytes)
}
details_test_no_details :: proc(doc: Document) -> bool {
	for block in doc.blocks {if block.tag == .Details {return false}}
	return true
}

@(test)
details_opener_grammar :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	details_work_reset()
	a, a_ok := parse_details_opener_line("  <details>  ")
	testing.expect(t, a_ok && !a.open && a.tag_end == 11)
	for line in ([]string{"<DETAILS open>", "<details open=\"false\">"}) {
		b, ok := parse_details_opener_line(line)
		testing.expect(t, ok && b.open)
	}
	for line in ([]string{"<details opened>", "<details data-open=\"1\" class=\"open\">", "<details openx>", "<details foo='open'>", "<details title=\"a>b\">"}) {
		b, ok := parse_details_opener_line(line)
		testing.expect(t, ok && !b.open)
	}
	for line in ([]string{"<detailsx>", "<details/>", "<details> trailing", "<details><summary>x</summary></details>"}) {
		_, ok := parse_details_opener_line(line)
		testing.expect(t, !ok)
	}
}

@(test)
details_closer_grammar :: proc(t: ^testing.T) {
	for line in ([]string{"  </details>  ", "</DETAILS>"}) {
		_, ok := parse_details_closer_line(line)
		testing.expect(t, ok)
	}
	for line in ([]string{"</details foo>", "</detailsx>"}) {
		_, ok := parse_details_closer_line(line)
		testing.expect(t, !ok)
	}
}

@(test)
summary_oneline_grammar :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a := parse_summary_line("<summary>Tap</summary>")
	testing.expect(t, a.kind == .Complete && a.inner == "Tap")
	b := parse_summary_line("<summary>`</summary>` more</summary>")
	testing.expect(t, b.kind == .Complete && b.inner == "`</summary>` more")
	c := parse_summary_line("<summary>")
	testing.expect(t, c.kind == .OpenOnly && c.after_open == "")
	testing.expect(t, parse_summary_line("<summary foo=>").kind == .Malformed)
	testing.expect(t, parse_summary_line("hello").kind == .NotSummary)
	testing.expect(t, parse_summary_line(details_test_repeat("`", 64)).kind == .NotSummary)
}

@(test)
summary_multiline_grammar :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	testing.expect(t, continue_summary("", "More **information**").kind == .StillOpen)
	a := continue_summary("More **information**", "</summary>")
	testing.expect(t, a.kind == .Complete && a.inner == "More **information**")
	b := continue_summary("use `literal", "</summary>` here</summary>")
	testing.expect(t, b.kind == .Complete && b.inner == "use `literal\n</summary>` here")
	c := summary_collector_from("`one")
	testing.expect(t, summary_push_line(&c, "</summary>", max(int)).kind == .StillOpen)
	testing.expect(t, summary_has_unmatched(&c))
	testing.expect(t, summary_push_line(&c, "</details>", max(int)).kind == .StillOpen)
	testing.expect(t, summary_push_line(&c, "two`", max(int)).kind == .StillOpen)
	testing.expect(t, !summary_has_unmatched(&c))
	end := summary_push_line(&c, "</summary>", max(int))
	testing.expect(t, end.kind == .Complete && end.inner == "`one\n</summary>\n</details>\ntwo`")
}

@(test)
summary_bounded_suffix :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	details_work_reset()
	huge := details_test_join("<summary>", details_test_repeat("z", 1_000_000))
	classified := parse_summary_line_bounded(huge, 16)
	testing.expect(t, classified.kind == .OpenOnly)
	testing.expect(t, len(classified.after_open) == 7)
	testing.expect(t, details_work_get() < 8_192)
}

@(test)
summary_backticks_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	prev: u64
	for n in ([]int{2_000, 4_000, 8_000, 16_000}) {
		details_work_reset()
		continue_summary("after", details_test_repeat("`", n))
		work := details_work_get()
		testing.expect(t, work <= u64(n * 8 + 256))
		if prev > 0 {testing.expect(t, work <= prev * 3)}
		prev = work
	}
}

@(test)
summary_deferred_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	for n in ([]int{500, 1_000, 2_000}) {
		details_work_reset()
		c := summary_collector_from("`")
		for _ in 0 ..< n {summary_push_line(&c, "</summary>", max(int))}
		for _ in 0 ..< n {summary_push_line(&c, "``code``", max(int))}
		work := details_work_get()
		testing.expect(t, work <= u64(len(summary_inner(&c)) * 16))
		_, _, ok := summary_finalize(&c)
		testing.expect(t, ok)
	}
}

@(test)
details_tag_inclusive_cap :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	pad := details_test_repeat("x", MAX_DETAILS_TAG_BYTES - len("<details class=''>"))
	exact := details_test_join("<details class='", pad, "'>")
	testing.expect(t, len(exact) == MAX_DETAILS_TAG_BYTES)
	_, exact_ok := parse_details_opener_line(exact)
	testing.expect(t, exact_ok)
	over := details_test_join("<details class='", pad, "y'>")
	testing.expect(t, len(over) > MAX_DETAILS_TAG_BYTES)
	_, over_ok := parse_details_opener_line(over)
	testing.expect(t, !over_ok)
}

@(test)
details_utf8_window :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	s := details_test_join(details_test_repeat("a", MAX_DETAILS_SCAN_BYTES - 1), "émore")
	w := details_window(s)
	testing.expect(t, w <= MAX_DETAILS_SCAN_BYTES)
	testing.expect(t, w == len(s) || s[w] & 0xc0 != 0x80)
	testing.expect(t, w == MAX_DETAILS_SCAN_BYTES - 1)
}

// These exercise the complete document parser, not just the local grammar:
// failed candidates must not make block-container processing quadratic.
@(test)
details_failed_openers_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	md := details_test_join(details_test_repeat("<details>\n", 200), "tail\n")
	doc := parse_document(md)
	testing.expect(t, details_test_no_details(doc))
	testing.expect(t, details_work_get() < 200 * 64)
}

@(test)
details_first_ticks_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	prev: u64
	for n in ([]int{4_000, 8_000, 16_000, 32_000}) {
		details_work_reset()
		parse_document(
			details_test_join("<details>\n", details_test_repeat("`", n), "\n</details>"),
		)
		work := details_work_get()
		testing.expect(t, work <= u64(n * 16 + 4_096))
		if prev > 0 {testing.expect(t, work <= prev * 3)}
		prev = work
	}
	details_work_reset()
	near_cap := min(65_519, MAX_DETAILS_SCAN_BYTES - 16)
	parse_document(
		details_test_join("<details>\n", details_test_repeat("`", near_cap), "\n</details>"),
	)
	testing.expect(t, details_work_get() <= u64(near_cap * 16 + 4_096))
}

@(test)
details_summary_ticks_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	prev: u64
	for n in ([]int{4_000, 8_000, 16_000, 32_000}) {
		details_work_reset()
		parse_document(
			details_test_join("<details>\n<summary>", details_test_repeat("`", n), "\n</details>"),
		)
		work := details_work_get()
		testing.expect(t, work <= u64(n * 16 + 4_096))
		if prev > 0 {testing.expect(t, work <= prev * 3)}
		prev = work
	}
}

@(test)
details_unequal_ticks_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	details_work_reset()
	bytes: [dynamic]u8
	append(&bytes, "<details>\n<summary>")
	for n in 1 ..= 64 {
		append(&bytes, ..transmute([]u8)details_test_repeat("`", n))
		append(&bytes, 'x')
	}
	append(&bytes, "\n</details>")
	parse_document(string(bytes[:]))
	testing.expect(t, details_work_get() < 64 * 64 * 8)
}

@(test)
details_multiline_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	prev: u64
	for n in ([]int{1_000, 2_000, 4_000, 8_000}) {
		details_work_reset()
		md := details_test_join(
			"<details>\n<summary>\n",
			details_test_repeat("x\n", n),
			"</details>",
		)
		parse_document(md)
		work := details_work_get()
		testing.expect(t, work <= u64(len(md) * 16 + 4_096))
		if prev > 0 {testing.expect(t, work <= prev * 3)}
		prev = work
	}
	details_work_reset()
	md := details_test_join("<details>\n<summary>\n", details_test_repeat("x\n", 32_000))
	parse_document(md)
	testing.expect(t, details_work_get() <= u64(len(md) * 16 + 4_096))
}

@(test)
details_deferred_linear :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	for n in ([]int{500, 1_000, 2_000}) {
		md := details_test_join(
			"<details>\n<summary>`\n",
			details_test_repeat("</summary>\n", n),
			details_test_repeat("``code``\n", n),
		)
		parse_document(md)
		testing.expect(t, details_work_get() <= u64(len(md) * 16 + 4_096))
	}
}
