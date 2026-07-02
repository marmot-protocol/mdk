//! UniFFI-friendly Markdown AST values.
//!
//! The parser crate owns the real AST. These records/enums keep the generated
//! Swift/Kotlin surface stable and host-friendly.

use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN;
use marmot_markdown::{
    Alignment as MdAlignment, AutolinkKind as MdAutolinkKind, Block as MdBlock,
    CodeBlockKind as MdCodeBlockKind, Document as MdDocument, Inline as MdInline,
    ListItem as MdListItem, ListKind as MdListKind, NostrEntity as MdNostrEntity,
    NostrHrp as MdNostrHrp, TableCell as MdTableCell,
};

const MAX_FFI_MARKDOWN_DEPTH: usize = 128;
const MAX_FFI_MARKDOWN_INPUT_BYTES: usize = AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize;

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownDocumentFfi {
    pub blocks: Vec<MarkdownBlockFfi>,
    /// True when the input exceeded the FFI Markdown safety cap and `blocks`
    /// were parsed from a UTF-8-boundary prefix.
    pub truncated: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownBlockFfi {
    Paragraph {
        inlines: Vec<MarkdownInlineFfi>,
    },
    Heading {
        level: u8,
        inlines: Vec<MarkdownInlineFfi>,
    },
    ThematicBreak,
    CodeBlock {
        kind: MarkdownCodeBlockKindFfi,
        info: String,
        content: String,
    },
    BlockQuote {
        blocks: Vec<MarkdownBlockFfi>,
    },
    List {
        kind: MarkdownListKindFfi,
        tight: bool,
        items: Vec<MarkdownListItemFfi>,
    },
    Table {
        alignments: Vec<MarkdownAlignmentFfi>,
        header: Vec<MarkdownTableCellFfi>,
        rows: Vec<Vec<MarkdownTableCellFfi>>,
    },
    MathBlock {
        content: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownCodeBlockKindFfi {
    Indented,
    Fenced,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownListKindFfi {
    /// `marker` is a single-character string: "-", "*", or "+".
    Bullet { marker: String },
    /// `delimiter` is a single-character string: "." or ")".
    Ordered { start: u32, delimiter: String },
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownListItemFfi {
    pub blocks: Vec<MarkdownBlockFfi>,
    /// `None` for plain bullets/ordered items, `Some(false)` for `[ ]`,
    /// `Some(true)` for `[x]`.
    pub checked: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownAlignmentFfi {
    None,
    Left,
    Center,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownTableCellFfi {
    pub inlines: Vec<MarkdownInlineFfi>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownInlineFfi {
    Text {
        content: String,
    },
    SoftBreak,
    HardBreak,
    Code {
        content: String,
    },
    Emph {
        children: Vec<MarkdownInlineFfi>,
    },
    Strong {
        children: Vec<MarkdownInlineFfi>,
    },
    Strikethrough {
        children: Vec<MarkdownInlineFfi>,
    },
    Link {
        dest: String,
        title: Option<String>,
        children: Vec<MarkdownInlineFfi>,
    },
    Image {
        dest: String,
        title: Option<String>,
        alt: Vec<MarkdownInlineFfi>,
    },
    Autolink {
        url: String,
        kind: MarkdownAutolinkKindFfi,
    },
    Math {
        content: String,
    },
    NostrMention {
        entity: MarkdownNostrEntityFfi,
    },
    NostrUri {
        entity: MarkdownNostrEntityFfi,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownAutolinkKindFfi {
    Uri,
    Email,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownNostrEntityFfi {
    pub hrp: MarkdownNostrHrpFfi,
    pub bech32: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownNostrHrpFfi {
    Npub,
    Note,
    Nevent,
    Nprofile,
    Naddr,
    Nrelay,
}

pub(crate) fn parse_markdown_document(text: &str) -> MarkdownDocumentFfi {
    let input = markdown_input_within_ffi_limit(text);
    let mut document: MarkdownDocumentFfi = marmot_markdown::parse(input.text).into();
    document.truncated = input.truncated;
    document
}

struct LimitedMarkdownInput<'a> {
    text: &'a str,
    truncated: bool,
}

fn markdown_input_within_ffi_limit(text: &str) -> LimitedMarkdownInput<'_> {
    if text.len() <= MAX_FFI_MARKDOWN_INPUT_BYTES {
        return LimitedMarkdownInput {
            text,
            truncated: false,
        };
    }

    let mut end = MAX_FFI_MARKDOWN_INPUT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    LimitedMarkdownInput {
        text: &text[..end],
        truncated: true,
    }
}

impl From<&MdDocument> for MarkdownDocumentFfi {
    fn from(value: &MdDocument) -> Self {
        Self {
            blocks: value
                .blocks
                .iter()
                .map(|block| markdown_block_from_md(block, 0))
                .collect(),
            truncated: false,
        }
    }
}

impl From<MdDocument> for MarkdownDocumentFfi {
    fn from(value: MdDocument) -> Self {
        (&value).into()
    }
}

impl From<&MdBlock> for MarkdownBlockFfi {
    fn from(value: &MdBlock) -> Self {
        markdown_block_from_md(value, 0)
    }
}

fn markdown_block_from_md(value: &MdBlock, depth: usize) -> MarkdownBlockFfi {
    if depth >= MAX_FFI_MARKDOWN_DEPTH {
        return MarkdownBlockFfi::Paragraph {
            inlines: Vec::new(),
        };
    }
    match value {
        MdBlock::Paragraph { inlines } => MarkdownBlockFfi::Paragraph {
            inlines: markdown_inlines_from_md(inlines, 0),
        },
        MdBlock::Heading { level, inlines } => MarkdownBlockFfi::Heading {
            level: *level,
            inlines: markdown_inlines_from_md(inlines, 0),
        },
        MdBlock::ThematicBreak => MarkdownBlockFfi::ThematicBreak,
        MdBlock::CodeBlock {
            kind,
            info,
            content,
        } => MarkdownBlockFfi::CodeBlock {
            kind: (*kind).into(),
            info: info.clone(),
            content: content.clone(),
        },
        MdBlock::BlockQuote { blocks } => MarkdownBlockFfi::BlockQuote {
            blocks: blocks
                .iter()
                .map(|block| markdown_block_from_md(block, depth + 1))
                .collect(),
        },
        MdBlock::List { kind, tight, items } => MarkdownBlockFfi::List {
            kind: kind.into(),
            tight: *tight,
            items: items
                .iter()
                .map(|item| markdown_list_item_from_md(item, depth + 1))
                .collect(),
        },
        MdBlock::Table {
            alignments,
            header,
            rows,
        } => MarkdownBlockFfi::Table {
            alignments: alignments
                .iter()
                .map(|alignment| (*alignment).into())
                .collect(),
            header: header.iter().map(markdown_table_cell_from_md).collect(),
            rows: rows
                .iter()
                .map(|row| row.iter().map(markdown_table_cell_from_md).collect())
                .collect(),
        },
        MdBlock::MathBlock { content } => MarkdownBlockFfi::MathBlock {
            content: content.clone(),
        },
    }
}

impl From<MdCodeBlockKind> for MarkdownCodeBlockKindFfi {
    fn from(value: MdCodeBlockKind) -> Self {
        match value {
            MdCodeBlockKind::Indented => Self::Indented,
            MdCodeBlockKind::Fenced => Self::Fenced,
        }
    }
}

impl From<&MdListKind> for MarkdownListKindFfi {
    fn from(value: &MdListKind) -> Self {
        match *value {
            MdListKind::Bullet { marker } => Self::Bullet {
                marker: (marker as char).to_string(),
            },
            MdListKind::Ordered { start, delimiter } => Self::Ordered {
                start,
                delimiter: (delimiter as char).to_string(),
            },
        }
    }
}

impl From<&MdListItem> for MarkdownListItemFfi {
    fn from(value: &MdListItem) -> Self {
        markdown_list_item_from_md(value, 0)
    }
}

fn markdown_list_item_from_md(value: &MdListItem, depth: usize) -> MarkdownListItemFfi {
    MarkdownListItemFfi {
        blocks: value
            .blocks
            .iter()
            .map(|block| markdown_block_from_md(block, depth))
            .collect(),
        checked: value.checked,
    }
}

impl From<MdAlignment> for MarkdownAlignmentFfi {
    fn from(value: MdAlignment) -> Self {
        match value {
            MdAlignment::None => Self::None,
            MdAlignment::Left => Self::Left,
            MdAlignment::Center => Self::Center,
            MdAlignment::Right => Self::Right,
        }
    }
}

impl From<&MdTableCell> for MarkdownTableCellFfi {
    fn from(value: &MdTableCell) -> Self {
        markdown_table_cell_from_md(value)
    }
}

fn markdown_table_cell_from_md(value: &MdTableCell) -> MarkdownTableCellFfi {
    MarkdownTableCellFfi {
        inlines: markdown_inlines_from_md(&value.inlines, 0),
    }
}

impl From<&MdInline> for MarkdownInlineFfi {
    fn from(value: &MdInline) -> Self {
        markdown_inline_from_md(value, 0)
    }
}

fn markdown_inlines_from_md(values: &[MdInline], depth: usize) -> Vec<MarkdownInlineFfi> {
    values
        .iter()
        .map(|value| markdown_inline_from_md(value, depth))
        .collect()
}

fn markdown_inline_from_md(value: &MdInline, depth: usize) -> MarkdownInlineFfi {
    if depth >= MAX_FFI_MARKDOWN_DEPTH {
        return MarkdownInlineFfi::Text {
            content: String::new(),
        };
    }
    match value {
        MdInline::Text(content) => MarkdownInlineFfi::Text {
            content: content.clone(),
        },
        MdInline::SoftBreak => MarkdownInlineFfi::SoftBreak,
        MdInline::HardBreak => MarkdownInlineFfi::HardBreak,
        MdInline::Code(content) => MarkdownInlineFfi::Code {
            content: content.clone(),
        },
        MdInline::Emph(children) => MarkdownInlineFfi::Emph {
            children: markdown_inlines_from_md(children, depth + 1),
        },
        MdInline::Strong(children) => MarkdownInlineFfi::Strong {
            children: markdown_inlines_from_md(children, depth + 1),
        },
        MdInline::Strikethrough(children) => MarkdownInlineFfi::Strikethrough {
            children: markdown_inlines_from_md(children, depth + 1),
        },
        MdInline::Link {
            dest,
            title,
            children,
        } => MarkdownInlineFfi::Link {
            dest: dest.clone(),
            title: title.clone(),
            children: markdown_inlines_from_md(children, depth + 1),
        },
        MdInline::Image { dest, title, alt } => MarkdownInlineFfi::Image {
            dest: dest.clone(),
            title: title.clone(),
            alt: markdown_inlines_from_md(alt, depth + 1),
        },
        MdInline::Autolink { url, kind } => MarkdownInlineFfi::Autolink {
            url: url.clone(),
            kind: (*kind).into(),
        },
        MdInline::Math(content) => MarkdownInlineFfi::Math {
            content: content.clone(),
        },
        MdInline::NostrMention(entity) => MarkdownInlineFfi::NostrMention {
            entity: entity.into(),
        },
        MdInline::NostrUri(entity) => MarkdownInlineFfi::NostrUri {
            entity: entity.into(),
        },
    }
}

impl From<MdAutolinkKind> for MarkdownAutolinkKindFfi {
    fn from(value: MdAutolinkKind) -> Self {
        match value {
            MdAutolinkKind::Uri => Self::Uri,
            MdAutolinkKind::Email => Self::Email,
        }
    }
}

impl From<&MdNostrEntity> for MarkdownNostrEntityFfi {
    fn from(value: &MdNostrEntity) -> Self {
        Self {
            hrp: value.hrp.into(),
            bech32: value.bech32.clone(),
        }
    }
}

impl From<MdNostrHrp> for MarkdownNostrHrpFfi {
    fn from(value: MdNostrHrp) -> Self {
        match value {
            MdNostrHrp::Npub => Self::Npub,
            MdNostrHrp::Note => Self::Note,
            MdNostrHrp::Nevent => Self::Nevent,
            MdNostrHrp::Nprofile => Self::Nprofile,
            MdNostrHrp::Naddr => Self::Naddr,
            MdNostrHrp::Nrelay => Self::Nrelay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_document() {
        assert_eq!(parse_markdown_document(""), MarkdownDocumentFfi::default());
    }

    #[test]
    fn caps_markdown_input_at_plaintext_frame_limit() {
        let input = "a".repeat(MAX_FFI_MARKDOWN_INPUT_BYTES + 16);
        let capped = markdown_input_within_ffi_limit(&input);

        assert_eq!(capped.text.len(), MAX_FFI_MARKDOWN_INPUT_BYTES);
        assert!(capped.truncated);
    }

    #[test]
    fn markdown_input_cap_preserves_utf8_boundary() {
        let input = format!("{}🦫", "a".repeat(MAX_FFI_MARKDOWN_INPUT_BYTES - 1));
        let capped = markdown_input_within_ffi_limit(&input);

        assert_eq!(capped.text, "a".repeat(MAX_FFI_MARKDOWN_INPUT_BYTES - 1));
        assert!(capped.truncated);
    }

    #[test]
    fn parse_markdown_document_applies_input_cap() {
        let document = parse_markdown_document(&"a".repeat(MAX_FFI_MARKDOWN_INPUT_BYTES + 16));
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(
            &inlines[0],
            MarkdownInlineFfi::Text { content } if content.len() == MAX_FFI_MARKDOWN_INPUT_BYTES
        ));
        assert!(document.truncated);
    }

    #[test]
    fn bridges_emphasis_strike_and_link() {
        let document = parse_markdown_document("**bold** ~~gone~~ [site](https://example.com)");
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(inlines[0], MarkdownInlineFfi::Strong { .. }));
        assert!(matches!(
            inlines[2],
            MarkdownInlineFfi::Strikethrough { .. }
        ));
        assert!(matches!(
            inlines[4],
            MarkdownInlineFfi::Link { ref dest, .. } if dest == "https://example.com"
        ));
    }

    #[test]
    fn bridges_nostr_entities() {
        let body = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let document = parse_markdown_document(&format!("@npub1{body} nostr:npub1{body}"));
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(
            inlines[0],
            MarkdownInlineFfi::NostrMention {
                entity: MarkdownNostrEntityFfi {
                    hrp: MarkdownNostrHrpFfi::Npub,
                    ..
                }
            }
        ));
        assert!(matches!(
            inlines[2],
            MarkdownInlineFfi::NostrUri {
                entity: MarkdownNostrEntityFfi {
                    hrp: MarkdownNostrHrpFfi::Npub,
                    ..
                }
            }
        ));
    }

    #[test]
    fn bridges_darkmatter_autolink() {
        let document = parse_markdown_document("open darkmatter://profile/npub1abc");
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(
            inlines[1],
            MarkdownInlineFfi::Autolink { ref url, .. } if url == "darkmatter://profile/npub1abc"
        ));
    }

    #[test]
    fn bridges_table() {
        let document = parse_markdown_document("| a | b |\n| :- | -: |\n| 1 | 2 |");
        assert!(matches!(
            document.blocks[0],
            MarkdownBlockFfi::Table {
                ref alignments,
                ref header,
                ref rows,
            } if alignments == &[MarkdownAlignmentFfi::Left, MarkdownAlignmentFfi::Right]
                && header.len() == 2
                && rows.len() == 1
        ));
    }

    #[test]
    fn bridges_pathological_nesting_without_unbounded_recursion() {
        let document = parse_markdown_document(&">".repeat(2_000));
        assert!(max_block_depth(&document.blocks) <= MAX_FFI_MARKDOWN_DEPTH);
    }

    fn max_block_depth(blocks: &[MarkdownBlockFfi]) -> usize {
        blocks.iter().map(max_single_block_depth).max().unwrap_or(0)
    }

    fn max_single_block_depth(block: &MarkdownBlockFfi) -> usize {
        match block {
            MarkdownBlockFfi::BlockQuote { blocks } => 1 + max_block_depth(blocks),
            MarkdownBlockFfi::List { items, .. } => {
                1 + items
                    .iter()
                    .map(|item| max_block_depth(&item.blocks))
                    .max()
                    .unwrap_or(0)
            }
            _ => 1,
        }
    }
}
