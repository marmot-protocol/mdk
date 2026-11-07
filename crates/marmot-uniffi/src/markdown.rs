//! UniFFI-friendly Markdown AST values.
//!
//! The parser crate owns the real AST. These records/enums keep the generated
//! Swift/Kotlin surface stable and host-friendly.
//!
//! Destination classifications are renderer-policy input, not authorization.
//! Hosts must inspect them before navigating to a link or fetching an image;
//! the original untrusted destination is intentionally preserved.

use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN;
use marmot_markdown::{
    Alignment as MdAlignment, AutolinkKind as MdAutolinkKind, Block as MdBlock,
    CodeBlockKind as MdCodeBlockKind, Document as MdDocument, Inline as MdInline,
    LinkDestinationKind as MdLinkDestinationKind, ListItem as MdListItem, ListKind as MdListKind,
    NostrEntity as MdNostrEntity, NostrHrp as MdNostrHrp, TableCell as MdTableCell,
    TimestampStyle as MdTimestampStyle,
};

const MAX_FFI_MARKDOWN_DEPTH: usize = 128;
const MAX_FFI_MARKDOWN_INPUT_BYTES: usize = AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize;

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownDocumentFfi {
    pub blocks: Vec<MarkdownBlockFfi>,
    /// True when the input exceeded the FFI Markdown safety cap and `blocks`
    /// were parsed from a UTF-8-boundary prefix.
    pub truncated: bool,
    /// Blank source lines before each corresponding block, clamped by
    /// `marmot-markdown` to its documented maximum.
    pub blank_lines_before: Vec<u8>,
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
        /// Blank source lines before each corresponding child block.
        blank_lines_before: Vec<u8>,
    },
    /// Named `ListBlock` (not `List`) to match the sibling `*Block` variants and
    /// to avoid shadowing `kotlin.collections.List` in generated Kotlin bindings.
    ListBlock {
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
    Details {
        summary: Vec<MarkdownInlineFfi>,
        open: bool,
        body: Vec<MarkdownBlockFfi>,
        /// Blank source lines before each corresponding body block.
        blank_lines_before: Vec<u8>,
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
    /// Blank source lines before each corresponding child block.
    pub blank_lines_before: Vec<u8>,
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
        classification: MarkdownLinkDestinationKindFfi,
    },
    Image {
        dest: String,
        title: Option<String>,
        alt: Vec<MarkdownInlineFfi>,
        classification: MarkdownLinkDestinationKindFfi,
    },
    Autolink {
        url: String,
        kind: MarkdownAutolinkKindFfi,
        classification: MarkdownLinkDestinationKindFfi,
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
    /// Signed Unix seconds and a display style, formatted by the host at render time.
    Timestamp {
        unix_seconds: i64,
        style: MarkdownTimestampStyleFfi,
    },
}

/// Timestamp display styles, using the device locale and timezone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownTimestampStyleFfi {
    /// `t`: time without seconds.
    ShortTime,
    /// `T`: time including seconds.
    LongTime,
    /// `d`: short date.
    ShortDate,
    /// `D`: long date.
    LongDate,
    /// `f` or omitted: long date and time without seconds.
    ShortDateTime,
    /// `F`: weekday, long date and time without seconds.
    LongDateTime,
    /// `s`: short date and time without seconds.
    CompactDateTime,
    /// `S`: short date and time including seconds.
    CompactDateTimeSeconds,
    /// `R`: time relative to the host's current clock; refresh while visible.
    Relative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownAutolinkKindFfi {
    Uri,
    Email,
    /// Bare `www.` host/path text. Hosts synthesize `https://` for navigation.
    Www,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownLinkDestinationKindFfi {
    Web,
    Contact,
    App,
    Nostr,
    Relative,
    Unknown,
    Dangerous,
    Sensitive,
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

/// Owned conversions throughout: the parse in [`parse_markdown_document`] is
/// the only producer of these ASTs, and it hands the document over for good,
/// so every string moves into the FFI value instead of being cloned. This
/// halves the allocation cost of converting a parsed message.
impl From<MdDocument> for MarkdownDocumentFfi {
    fn from(value: MdDocument) -> Self {
        Self {
            blocks: value
                .blocks
                .into_iter()
                .map(|block| markdown_block_from_md(block, 0))
                .collect(),
            truncated: false,
            blank_lines_before: value.blank_lines_before,
        }
    }
}

fn markdown_block_from_md(value: MdBlock, depth: usize) -> MarkdownBlockFfi {
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
            level,
            inlines: markdown_inlines_from_md(inlines, 0),
        },
        MdBlock::ThematicBreak => MarkdownBlockFfi::ThematicBreak,
        MdBlock::CodeBlock {
            kind,
            info,
            content,
        } => MarkdownBlockFfi::CodeBlock {
            kind: kind.into(),
            info,
            content,
        },
        MdBlock::BlockQuote {
            blocks,
            blank_lines_before,
        } => MarkdownBlockFfi::BlockQuote {
            blocks: blocks
                .into_iter()
                .map(|block| markdown_block_from_md(block, depth + 1))
                .collect(),
            blank_lines_before,
        },
        MdBlock::List { kind, tight, items } => MarkdownBlockFfi::ListBlock {
            kind: kind.into(),
            tight,
            items: items
                .into_iter()
                .map(|item| markdown_list_item_from_md(item, depth + 1))
                .collect(),
        },
        MdBlock::Table {
            alignments,
            header,
            rows,
        } => MarkdownBlockFfi::Table {
            alignments: alignments.into_iter().map(Into::into).collect(),
            header: header
                .into_iter()
                .map(markdown_table_cell_from_md)
                .collect(),
            rows: rows
                .into_iter()
                .map(|row| row.into_iter().map(markdown_table_cell_from_md).collect())
                .collect(),
        },
        MdBlock::MathBlock { content } => MarkdownBlockFfi::MathBlock { content },
        MdBlock::Details {
            summary,
            open,
            body,
            blank_lines_before,
        } => MarkdownBlockFfi::Details {
            summary: markdown_inlines_from_md(summary, 0),
            open,
            body: body
                .into_iter()
                .map(|block| markdown_block_from_md(block, depth + 1))
                .collect(),
            blank_lines_before,
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

impl From<MdListKind> for MarkdownListKindFfi {
    fn from(value: MdListKind) -> Self {
        match value {
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

fn markdown_list_item_from_md(value: MdListItem, depth: usize) -> MarkdownListItemFfi {
    MarkdownListItemFfi {
        blocks: value
            .blocks
            .into_iter()
            .map(|block| markdown_block_from_md(block, depth))
            .collect(),
        checked: value.checked,
        blank_lines_before: value.blank_lines_before,
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

fn markdown_table_cell_from_md(value: MdTableCell) -> MarkdownTableCellFfi {
    MarkdownTableCellFfi {
        inlines: markdown_inlines_from_md(value.inlines, 0),
    }
}

fn markdown_inlines_from_md(values: Vec<MdInline>, depth: usize) -> Vec<MarkdownInlineFfi> {
    values
        .into_iter()
        .map(|value| markdown_inline_from_md(value, depth))
        .collect()
}

fn markdown_inline_from_md(value: MdInline, depth: usize) -> MarkdownInlineFfi {
    if depth >= MAX_FFI_MARKDOWN_DEPTH {
        return MarkdownInlineFfi::Text {
            content: String::new(),
        };
    }
    match value {
        MdInline::Text(content) => MarkdownInlineFfi::Text { content },
        MdInline::SoftBreak => MarkdownInlineFfi::SoftBreak,
        MdInline::HardBreak => MarkdownInlineFfi::HardBreak,
        MdInline::Code(content) => MarkdownInlineFfi::Code { content },
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
            classification,
        } => MarkdownInlineFfi::Link {
            dest,
            title,
            children: markdown_inlines_from_md(children, depth + 1),
            classification: classification.into(),
        },
        MdInline::Image {
            dest,
            title,
            alt,
            classification,
        } => MarkdownInlineFfi::Image {
            dest,
            title,
            alt: markdown_inlines_from_md(alt, depth + 1),
            classification: classification.into(),
        },
        MdInline::Autolink {
            url,
            kind,
            classification,
        } => MarkdownInlineFfi::Autolink {
            url,
            kind: kind.into(),
            classification: classification.into(),
        },
        MdInline::Math(content) => MarkdownInlineFfi::Math { content },
        MdInline::NostrMention(entity) => MarkdownInlineFfi::NostrMention {
            entity: entity.into(),
        },
        MdInline::NostrUri(entity) => MarkdownInlineFfi::NostrUri {
            entity: entity.into(),
        },
        MdInline::Timestamp {
            unix_seconds,
            style,
        } => MarkdownInlineFfi::Timestamp {
            unix_seconds,
            style: style.into(),
        },
    }
}

impl From<MdTimestampStyle> for MarkdownTimestampStyleFfi {
    fn from(value: MdTimestampStyle) -> Self {
        match value {
            MdTimestampStyle::ShortTime => Self::ShortTime,
            MdTimestampStyle::LongTime => Self::LongTime,
            MdTimestampStyle::ShortDate => Self::ShortDate,
            MdTimestampStyle::LongDate => Self::LongDate,
            MdTimestampStyle::ShortDateTime => Self::ShortDateTime,
            MdTimestampStyle::LongDateTime => Self::LongDateTime,
            MdTimestampStyle::CompactDateTime => Self::CompactDateTime,
            MdTimestampStyle::CompactDateTimeSeconds => Self::CompactDateTimeSeconds,
            MdTimestampStyle::Relative => Self::Relative,
        }
    }
}

impl From<MdAutolinkKind> for MarkdownAutolinkKindFfi {
    fn from(value: MdAutolinkKind) -> Self {
        match value {
            MdAutolinkKind::Uri => Self::Uri,
            MdAutolinkKind::Email => Self::Email,
            MdAutolinkKind::Www => Self::Www,
        }
    }
}

impl From<MdLinkDestinationKind> for MarkdownLinkDestinationKindFfi {
    fn from(value: MdLinkDestinationKind) -> Self {
        match value {
            MdLinkDestinationKind::Web => Self::Web,
            MdLinkDestinationKind::Contact => Self::Contact,
            MdLinkDestinationKind::App => Self::App,
            MdLinkDestinationKind::Nostr => Self::Nostr,
            MdLinkDestinationKind::Relative => Self::Relative,
            MdLinkDestinationKind::Unknown => Self::Unknown,
            MdLinkDestinationKind::Dangerous => Self::Dangerous,
            MdLinkDestinationKind::Sensitive => Self::Sensitive,
        }
    }
}

impl From<MdNostrEntity> for MarkdownNostrEntityFfi {
    fn from(value: MdNostrEntity) -> Self {
        Self {
            hrp: value.hrp.into(),
            bech32: value.bech32,
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

    fn text(content: &str) -> MarkdownInlineFfi {
        MarkdownInlineFfi::Text {
            content: content.into(),
        }
    }

    fn paragraph(content: &str) -> MarkdownBlockFfi {
        MarkdownBlockFfi::Paragraph {
            inlines: vec![text(content)],
        }
    }

    #[test]
    fn bridges_timestamp_seconds_and_each_display_style() {
        for (suffix, style) in [
            ("t", MarkdownTimestampStyleFfi::ShortTime),
            ("T", MarkdownTimestampStyleFfi::LongTime),
            ("d", MarkdownTimestampStyleFfi::ShortDate),
            ("D", MarkdownTimestampStyleFfi::LongDate),
            ("f", MarkdownTimestampStyleFfi::ShortDateTime),
            ("F", MarkdownTimestampStyleFfi::LongDateTime),
            ("s", MarkdownTimestampStyleFfi::CompactDateTime),
            ("S", MarkdownTimestampStyleFfi::CompactDateTimeSeconds),
            ("R", MarkdownTimestampStyleFfi::Relative),
        ] {
            assert_eq!(
                parse_markdown_document(&format!("<t:-42:{suffix}>")).blocks,
                vec![MarkdownBlockFfi::Paragraph {
                    inlines: vec![MarkdownInlineFfi::Timestamp {
                        unix_seconds: -42,
                        style
                    }]
                }]
            );
        }
    }

    #[test]
    fn bridges_remaining_block_payloads_and_nested_quote() {
        for (input, expected) in [
            (
                "### title",
                MarkdownBlockFfi::Heading {
                    level: 3,
                    inlines: vec![text("title")],
                },
            ),
            ("---", MarkdownBlockFfi::ThematicBreak),
            (
                "    code",
                MarkdownBlockFfi::CodeBlock {
                    kind: MarkdownCodeBlockKindFfi::Indented,
                    info: String::new(),
                    content: "code\n".into(),
                },
            ),
            (
                "```rust\nlet x = 1;\n```",
                MarkdownBlockFfi::CodeBlock {
                    kind: MarkdownCodeBlockKindFfi::Fenced,
                    info: "rust".into(),
                    content: "let x = 1;\n".into(),
                },
            ),
            (
                "$$\nx+y\n$$",
                MarkdownBlockFfi::MathBlock {
                    content: "x+y\n".into(),
                },
            ),
            (
                "> ## nested",
                MarkdownBlockFfi::BlockQuote {
                    blocks: vec![MarkdownBlockFfi::Heading {
                        level: 2,
                        inlines: vec![text("nested")],
                    }],
                    blank_lines_before: vec![0],
                },
            ),
        ] {
            assert_eq!(
                parse_markdown_document(input).blocks,
                vec![expected],
                "input {input}"
            );
        }
    }

    #[test]
    fn bridges_inline_payloads_breaks_and_email_autolink() {
        for (input, inlines) in [
            (
                "a\nb",
                vec![text("a"), MarkdownInlineFfi::SoftBreak, text("b")],
            ),
            (
                "a  \nb",
                vec![text("a"), MarkdownInlineFfi::HardBreak, text("b")],
            ),
            (
                "`code`",
                vec![MarkdownInlineFfi::Code {
                    content: "code".into(),
                }],
            ),
            (
                "*em*",
                vec![MarkdownInlineFfi::Emph {
                    children: vec![text("em")],
                }],
            ),
            (
                "$x+y$",
                vec![MarkdownInlineFfi::Math {
                    content: "x+y".into(),
                }],
            ),
            (
                "<a@example.com>",
                vec![MarkdownInlineFfi::Autolink {
                    url: "a@example.com".into(),
                    kind: MarkdownAutolinkKindFfi::Email,
                    classification: MarkdownLinkDestinationKindFfi::Contact,
                }],
            ),
        ] {
            assert_eq!(
                parse_markdown_document(input).blocks,
                vec![MarkdownBlockFfi::Paragraph { inlines }],
                "input {input}"
            );
        }
    }

    #[test]
    fn parses_empty_document() {
        assert_eq!(parse_markdown_document(""), MarkdownDocumentFfi::default());
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
        assert_eq!(
            document.blocks,
            vec![MarkdownBlockFfi::Paragraph {
                inlines: vec![
                    MarkdownInlineFfi::Strong {
                        children: vec![text("bold")]
                    },
                    text(" "),
                    MarkdownInlineFfi::Strikethrough {
                        children: vec![text("gone")]
                    },
                    text(" "),
                    MarkdownInlineFfi::Link {
                        dest: "https://example.com".into(),
                        title: None,
                        children: vec![text("site")],
                        classification: MarkdownLinkDestinationKindFfi::Web
                    },
                ]
            }]
        );
    }

    #[test]
    fn bridges_explicit_destination_classification_without_dropping_targets() {
        for (destination, classification) in [
            ("https://example.com", MarkdownLinkDestinationKindFfi::Web),
            (
                "mailto:a@example.com",
                MarkdownLinkDestinationKindFfi::Contact,
            ),
            ("marmot://group/abc", MarkdownLinkDestinationKindFfi::App),
            ("nostr:npub1qqqqqq", MarkdownLinkDestinationKindFfi::Nostr),
            ("/relative/path", MarkdownLinkDestinationKindFfi::Relative),
            ("custom:payload", MarkdownLinkDestinationKindFfi::Unknown),
            (
                "javascript:alert(1)",
                MarkdownLinkDestinationKindFfi::Dangerous,
            ),
            (
                "nostr:ncryptsec1qqqqqq",
                MarkdownLinkDestinationKindFfi::Sensitive,
            ),
        ] {
            let document = parse_markdown_document(&format!(
                "[**label**]({destination} \"title\") ![*alt*]({destination} \"image\")"
            ));
            assert_eq!(
                document.blocks,
                vec![MarkdownBlockFfi::Paragraph {
                    inlines: vec![
                        MarkdownInlineFfi::Link {
                            dest: destination.into(),
                            title: Some("title".into()),
                            children: vec![MarkdownInlineFfi::Strong {
                                children: vec![text("label")]
                            }],
                            classification
                        },
                        text(" "),
                        MarkdownInlineFfi::Image {
                            dest: destination.into(),
                            title: Some("image".into()),
                            alt: vec![MarkdownInlineFfi::Emph {
                                children: vec![text("alt")]
                            }],
                            classification
                        },
                    ]
                }],
                "destination {destination}"
            );
        }
    }

    #[test]
    fn bridges_nostr_entities() {
        let body = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let npub = format!("npub1{body}");
        assert_eq!(
            parse_markdown_document(&format!("@{npub}")).blocks,
            vec![MarkdownBlockFfi::Paragraph {
                inlines: vec![MarkdownInlineFfi::NostrMention {
                    entity: MarkdownNostrEntityFfi {
                        hrp: MarkdownNostrHrpFfi::Npub,
                        bech32: npub
                    },
                }]
            }]
        );
        for (prefix, hrp) in [
            ("npub", MarkdownNostrHrpFfi::Npub),
            ("note", MarkdownNostrHrpFfi::Note),
            ("nevent", MarkdownNostrHrpFfi::Nevent),
            ("nprofile", MarkdownNostrHrpFfi::Nprofile),
            ("naddr", MarkdownNostrHrpFfi::Naddr),
            ("nrelay", MarkdownNostrHrpFfi::Nrelay),
        ] {
            let bech32 = format!("{prefix}1{body}");
            assert_eq!(
                parse_markdown_document(&format!("nostr:{bech32}")).blocks,
                vec![MarkdownBlockFfi::Paragraph {
                    inlines: vec![MarkdownInlineFfi::NostrUri {
                        entity: MarkdownNostrEntityFfi { hrp, bech32 },
                    }]
                }]
            );
        }
    }

    #[test]
    fn bridges_marmot_autolink() {
        let document = parse_markdown_document("open marmot://profile/npub1abc");
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(
            inlines[1],
            MarkdownInlineFfi::Autolink {
                ref url,
                classification: MarkdownLinkDestinationKindFfi::App,
                kind: MarkdownAutolinkKindFfi::Uri,
            } if url == "marmot://profile/npub1abc"
        ));
    }

    #[test]
    fn bridges_www_autolink_kind() {
        let document = parse_markdown_document("See www.example.com/path.");
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(
            inlines[0],
            MarkdownInlineFfi::Text { ref content } if content == "See "
        ));
        assert!(matches!(
            inlines[1],
            MarkdownInlineFfi::Autolink {
                ref url,
                kind: MarkdownAutolinkKindFfi::Www,
                classification: MarkdownLinkDestinationKindFfi::Web,
            } if url == "www.example.com/path"
        ));
        assert!(matches!(
            inlines[2],
            MarkdownInlineFfi::Text { ref content } if content == "."
        ));
    }

    #[test]
    fn bridges_dangerous_autolink_classification_without_dropping_url() {
        let document = parse_markdown_document("<javascript:alert(1)>");
        let MarkdownBlockFfi::Paragraph { inlines } = &document.blocks[0] else {
            panic!("expected paragraph");
        };
        assert!(matches!(
            inlines[0],
            MarkdownInlineFfi::Autolink {
                ref url,
                classification: MarkdownLinkDestinationKindFfi::Dangerous,
                ..
            } if url == "javascript:alert(1)"
        ));
    }

    #[test]
    fn bridges_table() {
        let document = parse_markdown_document(
            "| **a** | b | c | d |\n| :- | :-: | -: | -- |\n| 1 | `2` | 3 | 4 |",
        );
        let cell = |inlines| MarkdownTableCellFfi { inlines };
        assert_eq!(
            document.blocks,
            vec![MarkdownBlockFfi::Table {
                alignments: vec![
                    MarkdownAlignmentFfi::Left,
                    MarkdownAlignmentFfi::Center,
                    MarkdownAlignmentFfi::Right,
                    MarkdownAlignmentFfi::None
                ],
                header: vec![
                    cell(vec![MarkdownInlineFfi::Strong {
                        children: vec![text("a")]
                    }]),
                    cell(vec![text("b")]),
                    cell(vec![text("c")]),
                    cell(vec![text("d")])
                ],
                rows: vec![vec![
                    cell(vec![text("1")]),
                    cell(vec![MarkdownInlineFfi::Code {
                        content: "2".into()
                    }]),
                    cell(vec![text("3")]),
                    cell(vec![text("4")])
                ]],
            }]
        );
    }

    #[test]
    fn bridges_bullet_list() {
        for marker in ["-", "*", "+"] {
            let document = parse_markdown_document(&format!("{marker} [ ] a\n{marker} [x] b"));
            assert_eq!(
                document.blocks,
                vec![MarkdownBlockFfi::ListBlock {
                    kind: MarkdownListKindFfi::Bullet {
                        marker: marker.into()
                    },
                    tight: true,
                    items: vec![
                        MarkdownListItemFfi {
                            blocks: vec![paragraph("a")],
                            checked: Some(false),
                            blank_lines_before: vec![0]
                        },
                        MarkdownListItemFfi {
                            blocks: vec![paragraph("b")],
                            checked: Some(true),
                            blank_lines_before: vec![0]
                        }
                    ],
                }]
            );
        }
    }

    #[test]
    fn bridges_ordered_list_start_delimiter_and_loose_items() {
        for delimiter in [".", ")"] {
            let document =
                parse_markdown_document(&format!("7{delimiter} alpha\n\n8{delimiter} beta"));
            assert_eq!(
                document.blocks,
                vec![MarkdownBlockFfi::ListBlock {
                    kind: MarkdownListKindFfi::Ordered {
                        start: 7,
                        delimiter: delimiter.into()
                    },
                    tight: false,
                    items: vec![
                        MarkdownListItemFfi {
                            blocks: vec![paragraph("alpha")],
                            checked: None,
                            blank_lines_before: vec![0]
                        },
                        MarkdownListItemFfi {
                            blocks: vec![paragraph("beta")],
                            checked: None,
                            blank_lines_before: vec![0]
                        }
                    ],
                }]
            );
        }
    }

    #[test]
    fn bridges_blank_line_counts_for_every_block_owner() {
        let document =
            parse_markdown_document("first\n\n> quoted\n>\n> again\n\n- item\n\n  continuation");

        assert_eq!(document.blank_lines_before, [0, 1, 1]);
        let MarkdownBlockFfi::BlockQuote {
            blank_lines_before, ..
        } = &document.blocks[1]
        else {
            panic!("expected block quote");
        };
        assert_eq!(blank_lines_before, &[0, 1]);
        let MarkdownBlockFfi::ListBlock { items, .. } = &document.blocks[2] else {
            panic!("expected list");
        };
        assert_eq!(items[0].blank_lines_before, [0, 1]);
    }

    #[test]
    fn bridges_details_block() {
        for (attribute, open) in [("", false), (" open", true)] {
            let document = parse_markdown_document(&format!(
                "<details{attribute}>\n<summary>Tap to expand</summary>\nHidden body **bold**\n</details>"
            ));
            assert_eq!(
                document.blocks,
                vec![MarkdownBlockFfi::Details {
                    summary: vec![text("Tap to expand")],
                    open,
                    body: vec![MarkdownBlockFfi::Paragraph {
                        inlines: vec![
                            text("Hidden body "),
                            MarkdownInlineFfi::Strong {
                                children: vec![text("bold")]
                            }
                        ]
                    }],
                    blank_lines_before: vec![0],
                }]
            );
        }
    }

    #[test]
    fn bridges_multiline_summary_and_fallback_preserves_text() {
        let document = parse_markdown_document(
            "<details>\n<summary>\nMore **information**\n</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, body, .. } = &document.blocks[0] else {
            panic!("expected details");
        };
        assert!(
            summary
                .iter()
                .any(|inline| matches!(inline, MarkdownInlineFfi::Strong { .. }))
        );
        assert!(matches!(body[0], MarkdownBlockFfi::Paragraph { .. }));

        let fallback =
            parse_markdown_document("<details>\n<summary>KEEP_THIS_SUMMARY</summary>\nbody");
        assert!(
            !fallback
                .blocks
                .iter()
                .any(|block| matches!(block, MarkdownBlockFfi::Details { .. }))
        );
        assert!(fallback.blocks.iter().any(|block| match block {
            MarkdownBlockFfi::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
                inline,
                MarkdownInlineFfi::Text { content } if content.contains("KEEP_THIS_SUMMARY")
            )),
            _ => false,
        }));

        let later = parse_markdown_document(
            "<details>\n    code\n<summary>ordinary later text</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, body, .. } = &later.blocks[0] else {
            panic!("expected details after indented code");
        };
        assert!(summary.is_empty());
        assert!(body.iter().any(|block| match block {
            MarkdownBlockFfi::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
                inline,
                MarkdownInlineFfi::Text { content } if content.contains("<summary>ordinary later text</summary>")
            )),
            _ => false,
        }));

        let protected = parse_markdown_document(
            "<details>\n<summary>`one\n</summary>\n</details>\ntwo`\n</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, body, .. } = &protected.blocks[0] else {
            panic!("expected protected delimiter details");
        };
        assert!(
            summary
                .iter()
                .any(|inline| matches!(inline, MarkdownInlineFfi::Code { content } if content.contains("</details>")))
        );
        assert!(matches!(body[0], MarkdownBlockFfi::Paragraph { .. }));
        assert_eq!(protected.blocks.len(), 1);

        let code_span = parse_markdown_document(
            "<details>\n<summary>`one\n</summary>\ntwo`</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, .. } = &code_span.blocks[0] else {
            panic!("expected multiline code-span details");
        };
        assert!(
            summary
                .iter()
                .any(|inline| matches!(inline, MarkdownInlineFfi::Code { .. }))
        );

        let hard =
            parse_markdown_document("<details>\n<summary>one  \ntwo</summary>\nbody\n</details>");
        let MarkdownBlockFfi::Details { summary, .. } = &hard.blocks[0] else {
            panic!("expected hard-break details");
        };
        assert!(
            summary
                .iter()
                .any(|inline| matches!(inline, MarkdownInlineFfi::HardBreak))
        );
    }

    #[test]
    fn hostile_backtick_details_input_stays_bounded() {
        // The malformed details fallback is ordinary paragraph text, just as
        // in bridges_multiline_summary_and_fallback_preserves_text above.
        let contains_text = |document: &MarkdownDocumentFfi, expected: &str| {
            document.blocks.iter().any(|block| match block {
                MarkdownBlockFfi::Paragraph { inlines } => inlines.iter().any(|inline|
                    matches!(inline, MarkdownInlineFfi::Text { content } if content.contains(expected))),
                _ => false,
            })
        };
        let ticks = "`".repeat(65_519 - "<details>\n\n</details>".len());
        let document = parse_markdown_document(&format!("<details>\n{ticks}\n</details>"));
        assert!(!document.truncated);
        let summary_ticks = "`".repeat(8_192);
        let document = parse_markdown_document(&format!(
            "<details>\n<summary>{summary_ticks}KEEP_UNTERMINATED_SUMMARY\n</details>"
        ));
        assert!(!document.blocks.is_empty());
        assert!(contains_text(&document, "KEEP_UNTERMINATED_SUMMARY"));
        let mut many_lines = String::from("<details>\n<summary>\nKEEP_OPEN_SUMMARY_START\n");
        for _ in 0..4_096 {
            many_lines.push_str("x\n");
        }
        many_lines.push_str("KEEP_OPEN_SUMMARY_END");
        let document = parse_markdown_document(&many_lines);
        assert!(!document.blocks.is_empty());
        assert!(contains_text(&document, "KEEP_OPEN_SUMMARY_START"));
        assert!(contains_text(&document, "KEEP_OPEN_SUMMARY_END"));
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
            MarkdownBlockFfi::BlockQuote { blocks, .. }
            | MarkdownBlockFfi::Details { body: blocks, .. } => 1 + max_block_depth(blocks),
            MarkdownBlockFfi::ListBlock { items, .. } => {
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
