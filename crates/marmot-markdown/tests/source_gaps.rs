use marmot_markdown::{Block, MAX_SOURCE_BLANK_LINES, parse};

#[test]
fn document_blank_line_counts_distinguish_source_gaps() {
    assert_eq!(parse("first\n\nsecond").blank_lines_before, vec![0, 1]);
    assert_eq!(parse("first\n\n\nsecond").blank_lines_before, vec![0, 2]);
}

#[test]
fn trailing_indented_code_blanks_become_the_next_document_gap() {
    assert_eq!(
        parse("    code\n\nparagraph").blank_lines_before,
        vec![0, 1]
    );
    assert_eq!(
        parse("    code\n\n\nparagraph").blank_lines_before,
        vec![0, 2]
    );
}

#[test]
fn trailing_indented_code_blank_becomes_the_next_list_item_gap() {
    let document = parse("- text\n\n      code\n\n  continuation");
    let marmot_markdown::Block::List { items, .. } = &document.blocks[0] else {
        panic!("expected list");
    };

    assert_eq!(items[0].blank_lines_before, [0, 1, 1]);
}

#[test]
fn document_blank_line_counts_clamp_at_documented_maximum() {
    let input = format!("first\n{}second", "\n".repeat(300));

    assert_eq!(
        parse(&input).blank_lines_before,
        vec![0, MAX_SOURCE_BLANK_LINES]
    );
}

#[test]
fn block_quote_retains_blank_line_counts_for_its_blocks() {
    let document = parse("> first\n>\n>\n> second");
    let marmot_markdown::Block::BlockQuote {
        blank_lines_before, ..
    } = &document.blocks[0]
    else {
        panic!("expected block quote");
    };

    assert_eq!(blank_lines_before, &[0, 2]);
}

#[test]
fn marker_only_block_quote_opener_becomes_a_child_gap() {
    let document = parse(">\n> foo");
    let marmot_markdown::Block::BlockQuote {
        blocks,
        blank_lines_before,
    } = &document.blocks[0]
    else {
        panic!("expected block quote");
    };

    assert_eq!(blank_lines_before, &[1]);
    assert!(matches!(
        blocks.as_slice(),
        [marmot_markdown::Block::Paragraph { inlines }]
            if inlines == &[marmot_markdown::Inline::Text("foo".to_owned())]
    ));
}

#[test]
fn marker_only_nested_block_quote_opener_becomes_an_inner_child_gap() {
    let document = parse("> >\n> > foo");
    let marmot_markdown::Block::BlockQuote {
        blocks: outer_blocks,
        blank_lines_before: outer_gaps,
    } = &document.blocks[0]
    else {
        panic!("expected outer block quote");
    };
    let marmot_markdown::Block::BlockQuote {
        blocks: inner_blocks,
        blank_lines_before: inner_gaps,
    } = &outer_blocks[0]
    else {
        panic!("expected inner block quote");
    };

    assert_eq!(outer_gaps, &[0]);
    assert_eq!(inner_gaps, &[1]);
    assert!(matches!(
        inner_blocks.as_slice(),
        [marmot_markdown::Block::Paragraph { inlines }]
            if inlines == &[marmot_markdown::Inline::Text("foo".to_owned())]
    ));
}

#[test]
fn list_item_retains_blank_line_counts_for_its_blocks() {
    let document = parse("- first\n\n  second");
    let marmot_markdown::Block::List { items, .. } = &document.blocks[0] else {
        panic!("expected list");
    };

    assert_eq!(items[0].blank_lines_before, [0, 1]);
}

#[test]
fn blank_line_between_list_items_does_not_become_an_item_gap() {
    let document = parse("- first\n\n- second");
    let marmot_markdown::Block::List { items, .. } = &document.blocks[0] else {
        panic!("expected list");
    };

    assert_eq!(document.blank_lines_before, [0]);
    assert_eq!(items[0].blank_lines_before, [0]);
    assert_eq!(items[1].blank_lines_before, [0]);
}

#[test]
fn blank_line_before_atx_heading_keeps_preceding_list_loose() {
    let document = parse("- item\n\n# heading");

    assert_eq!(document.blank_lines_before, [0, 1]);
    assert!(matches!(
        document.blocks.as_slice(),
        [Block::List { tight: false, .. }, Block::Heading { .. }]
    ));
}

#[test]
fn blank_line_before_fenced_code_keeps_preceding_list_loose() {
    let document = parse("- item\n\n```\ncode\n```");

    assert_eq!(document.blank_lines_before, [0, 1]);
    assert!(matches!(
        document.blocks.as_slice(),
        [Block::List { tight: false, .. }, Block::CodeBlock { .. }]
    ));
}

#[test]
fn blank_line_before_block_quote_keeps_preceding_list_loose() {
    let document = parse("- item\n\n> quote");

    assert_eq!(document.blank_lines_before, [0, 1]);
    assert!(matches!(
        document.blocks.as_slice(),
        [Block::List { tight: false, .. }, Block::BlockQuote { .. }]
    ));
}

#[test]
fn blank_line_before_paragraph_keeps_preceding_list_loose() {
    let document = parse("- item\n\nparagraph");

    assert_eq!(document.blank_lines_before, [0, 1]);
    assert!(matches!(
        document.blocks.as_slice(),
        [Block::List { tight: false, .. }, Block::Paragraph { .. }]
    ));
}

#[test]
fn fenced_code_content_blank_lines_do_not_become_document_gaps() {
    let document = parse("```\nfirst\n\nsecond\n```\nafter");

    assert_eq!(document.blank_lines_before, [0, 0]);
    assert!(matches!(
        &document.blocks[0],
        marmot_markdown::Block::CodeBlock { content, .. } if content == "first\n\nsecond\n"
    ));
}

#[test]
fn trailing_blank_quote_marker_does_not_become_a_document_gap() {
    let document = parse("> quoted\n>\noutside");
    let marmot_markdown::Block::BlockQuote {
        blank_lines_before, ..
    } = &document.blocks[0]
    else {
        panic!("expected block quote");
    };

    assert_eq!(blank_lines_before, &[0]);
    assert_eq!(document.blank_lines_before, [0, 0]);
}

#[test]
fn trailing_nested_quote_marker_does_not_become_an_outer_quote_gap() {
    let document = parse("> outer\n> > inner\n> >\n> after");
    let marmot_markdown::Block::BlockQuote {
        blank_lines_before, ..
    } = &document.blocks[0]
    else {
        panic!("expected outer block quote");
    };

    assert_eq!(blank_lines_before, &[0, 0, 0]);
}

#[test]
fn blank_quote_marker_after_list_becomes_an_outer_quote_gap() {
    let document = parse("> - item\n>\n> after");
    let marmot_markdown::Block::BlockQuote {
        blocks,
        blank_lines_before,
    } = &document.blocks[0]
    else {
        panic!("expected outer block quote");
    };

    assert_eq!(blocks.len(), 2);
    assert_eq!(blank_lines_before, &[0, 1]);
}

#[test]
fn filtered_quote_markers_do_not_consume_the_root_gap_cap() {
    let input = format!(
        "> quoted\n{}\noutside",
        ">\n".repeat(MAX_SOURCE_BLANK_LINES as usize)
    );
    let document = parse(&input);

    assert_eq!(document.blank_lines_before, [0, 1]);
}

#[test]
fn adjacent_table_and_paragraph_do_not_gain_a_gap() {
    let document = parse("| h |\n| - |\n| a |\nafter");

    assert!(matches!(
        document.blocks[0],
        marmot_markdown::Block::Table { .. }
    ));
    assert_eq!(document.blank_lines_before, [0, 0]);
}

#[test]
fn inline_parsing_is_unchanged_by_source_gap_metadata() {
    let document = parse("before\n\n`code` and *emphasis*");
    let marmot_markdown::Block::Paragraph { inlines } = &document.blocks[1] else {
        panic!("second block should be a paragraph");
    };

    assert!(matches!(
        inlines.as_slice(),
        [
            marmot_markdown::Inline::Code(code),
            marmot_markdown::Inline::Text(space),
            marmot_markdown::Inline::Emph(_),
        ] if code == "code" && space == " and "
    ));
}

#[test]
fn details_and_code_spans_keep_their_existing_ast_shape() {
    let document = parse("<details>\n<summary>More</summary>\n\n`code`\n\n</details>");

    assert_eq!(document.blank_lines_before, vec![0, 1, 1]);
    let marmot_markdown::Block::Paragraph { inlines } = &document.blocks[1] else {
        panic!("code span should remain in a paragraph");
    };
    assert_eq!(inlines, &[marmot_markdown::Inline::Code("code".to_owned())]);
    let marmot_markdown::Block::Paragraph { inlines } = &document.blocks[2] else {
        panic!("closing details tag should remain paragraph text");
    };
    assert_eq!(
        inlines,
        &[marmot_markdown::Inline::Text("</details>".to_owned())]
    );
}
