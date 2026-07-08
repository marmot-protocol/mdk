//! C mirrors of the Markdown AST values (`marmot-uniffi/src/markdown.rs`).
//!
//! The parser crate owns the real AST; these mirrors keep the C surface
//! stable and host-friendly. All markdown types are outputs only: they are
//! produced by `marmot_parse_markdown` and embedded in timeline records,
//! and are never read back from caller memory.

use std::ffi::c_char;

use marmot_uniffi::{
    MarkdownAlignmentFfi, MarkdownAutolinkKindFfi, MarkdownBlockFfi, MarkdownCodeBlockKindFfi,
    MarkdownDocumentFfi, MarkdownInlineFfi, MarkdownListItemFfi, MarkdownListKindFfi,
    MarkdownNostrEntityFfi, MarkdownNostrHrpFfi, MarkdownTableCellFfi,
};

use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, owned_c_string, owned_opt_c_string, owned_vec,
};

/// Convert a vector of inline nodes into an owned `(ptr, len)` pair.
fn owned_inlines(values: Vec<MarkdownInlineFfi>) -> (*mut MarmotMarkdownInline, usize) {
    owned_vec(values.into_iter().map(Into::into).collect())
}

/// Convert a vector of block nodes into an owned `(ptr, len)` pair.
fn owned_blocks(values: Vec<MarkdownBlockFfi>) -> (*mut MarmotMarkdownBlock, usize) {
    owned_vec(values.into_iter().map(Into::into).collect())
}

/// A parsed Markdown document: the ordered top-level blocks.
#[repr(C)]
pub struct MarmotMarkdownDocument {
    pub blocks: *mut MarmotMarkdownBlock,
    pub blocks_len: usize,
    /// True when the input exceeded the FFI Markdown safety cap and the
    /// blocks were parsed from a UTF-8-boundary prefix.
    pub truncated: bool,
}

impl From<MarkdownDocumentFfi> for MarmotMarkdownDocument {
    fn from(value: MarkdownDocumentFfi) -> Self {
        let (blocks, blocks_len) = owned_blocks(value.blocks);
        Self {
            blocks,
            blocks_len,
            truncated: value.truncated,
        }
    }
}

impl CFree for MarmotMarkdownDocument {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.blocks, self.blocks_len) };
    }
}

/// Free a document returned by `marmot_parse_markdown`. Never call on
/// documents embedded by value inside another struct. NULL is a no-op.
///
/// # Safety
/// `document` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_markdown_document_free(document: *mut MarmotMarkdownDocument) {
    unsafe { free_boxed(document) };
}

/// One block-level Markdown node. Child blocks and inlines are owned
/// `(ptr, len)` arrays freed by the parent.
#[repr(C)]
pub enum MarmotMarkdownBlock {
    Paragraph {
        inlines: *mut MarmotMarkdownInline,
        inlines_len: usize,
    },
    Heading {
        level: u8,
        inlines: *mut MarmotMarkdownInline,
        inlines_len: usize,
    },
    ThematicBreak,
    CodeBlock {
        kind: MarmotMarkdownCodeBlockKind,
        info: *mut c_char,
        content: *mut c_char,
    },
    BlockQuote {
        blocks: *mut MarmotMarkdownBlock,
        blocks_len: usize,
    },
    /// Named `ListBlock` (not `List`) to match the sibling `*Block` variants.
    ListBlock {
        kind: MarmotMarkdownListKind,
        tight: bool,
        items: *mut MarmotMarkdownListItem,
        items_len: usize,
    },
    Table {
        alignments: *mut MarmotMarkdownAlignment,
        alignments_len: usize,
        header: *mut MarmotMarkdownTableCell,
        header_len: usize,
        rows: *mut MarmotMarkdownTableRow,
        rows_len: usize,
    },
    MathBlock {
        content: *mut c_char,
    },
}

impl From<MarkdownBlockFfi> for MarmotMarkdownBlock {
    fn from(value: MarkdownBlockFfi) -> Self {
        match value {
            MarkdownBlockFfi::Paragraph { inlines } => {
                let (inlines, inlines_len) = owned_inlines(inlines);
                Self::Paragraph {
                    inlines,
                    inlines_len,
                }
            }
            MarkdownBlockFfi::Heading { level, inlines } => {
                let (inlines, inlines_len) = owned_inlines(inlines);
                Self::Heading {
                    level,
                    inlines,
                    inlines_len,
                }
            }
            MarkdownBlockFfi::ThematicBreak => Self::ThematicBreak,
            MarkdownBlockFfi::CodeBlock {
                kind,
                info,
                content,
            } => Self::CodeBlock {
                kind: kind.into(),
                info: owned_c_string(info),
                content: owned_c_string(content),
            },
            MarkdownBlockFfi::BlockQuote { blocks } => {
                let (blocks, blocks_len) = owned_blocks(blocks);
                Self::BlockQuote { blocks, blocks_len }
            }
            MarkdownBlockFfi::ListBlock { kind, tight, items } => {
                let (items, items_len) = owned_vec(items.into_iter().map(Into::into).collect());
                Self::ListBlock {
                    kind: kind.into(),
                    tight,
                    items,
                    items_len,
                }
            }
            MarkdownBlockFfi::Table {
                alignments,
                header,
                rows,
            } => {
                let (alignments, alignments_len) =
                    owned_vec(alignments.into_iter().map(Into::into).collect());
                let (header, header_len) = owned_vec(header.into_iter().map(Into::into).collect());
                let (rows, rows_len) = owned_vec(rows.into_iter().map(Into::into).collect());
                Self::Table {
                    alignments,
                    alignments_len,
                    header,
                    header_len,
                    rows,
                    rows_len,
                }
            }
            MarkdownBlockFfi::MathBlock { content } => Self::MathBlock {
                content: owned_c_string(content),
            },
        }
    }
}

impl CFree for MarmotMarkdownBlock {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Paragraph {
                inlines,
                inlines_len,
            }
            | Self::Heading {
                inlines,
                inlines_len,
                ..
            } => unsafe { free_vec(*inlines, *inlines_len) },
            Self::ThematicBreak => {}
            Self::CodeBlock { info, content, .. } => unsafe {
                free_c_string(*info);
                free_c_string(*content);
            },
            Self::BlockQuote { blocks, blocks_len } => unsafe {
                free_vec(*blocks, *blocks_len);
            },
            Self::ListBlock {
                kind,
                items,
                items_len,
                ..
            } => unsafe {
                kind.free_in_place();
                free_vec(*items, *items_len);
            },
            Self::Table {
                alignments,
                alignments_len,
                header,
                header_len,
                rows,
                rows_len,
            } => unsafe {
                free_vec(*alignments, *alignments_len);
                free_vec(*header, *header_len);
                free_vec(*rows, *rows_len);
            },
            Self::MathBlock { content } => unsafe { free_c_string(*content) },
        }
    }
}

/// How a code block was written in the source text.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotMarkdownCodeBlockKind {
    Indented,
    Fenced,
}

impl From<MarkdownCodeBlockKindFfi> for MarmotMarkdownCodeBlockKind {
    fn from(value: MarkdownCodeBlockKindFfi) -> Self {
        match value {
            MarkdownCodeBlockKindFfi::Indented => Self::Indented,
            MarkdownCodeBlockKindFfi::Fenced => Self::Fenced,
        }
    }
}

impl CFree for MarmotMarkdownCodeBlockKind {
    unsafe fn free_in_place(&mut self) {}
}

/// List flavor: bullet or ordered.
#[repr(C)]
pub enum MarmotMarkdownListKind {
    /// `marker` is a single-character string: "-", "*", or "+".
    Bullet { marker: *mut c_char },
    /// `delimiter` is a single-character string: "." or ")".
    Ordered { start: u32, delimiter: *mut c_char },
}

impl From<MarkdownListKindFfi> for MarmotMarkdownListKind {
    fn from(value: MarkdownListKindFfi) -> Self {
        match value {
            MarkdownListKindFfi::Bullet { marker } => Self::Bullet {
                marker: owned_c_string(marker),
            },
            MarkdownListKindFfi::Ordered { start, delimiter } => Self::Ordered {
                start,
                delimiter: owned_c_string(delimiter),
            },
        }
    }
}

impl CFree for MarmotMarkdownListKind {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Bullet { marker } => unsafe { free_c_string(*marker) },
            Self::Ordered { delimiter, .. } => unsafe { free_c_string(*delimiter) },
        }
    }
}

/// One list item: nested blocks plus an optional task-list checkbox.
#[repr(C)]
pub struct MarmotMarkdownListItem {
    pub blocks: *mut MarmotMarkdownBlock,
    pub blocks_len: usize,
    /// `has_checked` is false for plain bullets/ordered items; otherwise
    /// `checked` is false for `[ ]` and true for `[x]`.
    pub has_checked: bool,
    pub checked: bool,
}

impl From<MarkdownListItemFfi> for MarmotMarkdownListItem {
    fn from(value: MarkdownListItemFfi) -> Self {
        let (blocks, blocks_len) = owned_blocks(value.blocks);
        Self {
            blocks,
            blocks_len,
            has_checked: value.checked.is_some(),
            checked: value.checked.unwrap_or(false),
        }
    }
}

impl CFree for MarmotMarkdownListItem {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.blocks, self.blocks_len) };
    }
}

/// Per-column table alignment.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotMarkdownAlignment {
    None,
    Left,
    Center,
    Right,
}

impl From<MarkdownAlignmentFfi> for MarmotMarkdownAlignment {
    fn from(value: MarkdownAlignmentFfi) -> Self {
        match value {
            MarkdownAlignmentFfi::None => Self::None,
            MarkdownAlignmentFfi::Left => Self::Left,
            MarkdownAlignmentFfi::Center => Self::Center,
            MarkdownAlignmentFfi::Right => Self::Right,
        }
    }
}

impl CFree for MarmotMarkdownAlignment {
    unsafe fn free_in_place(&mut self) {}
}

/// One table cell: a run of inline nodes.
#[repr(C)]
pub struct MarmotMarkdownTableCell {
    pub inlines: *mut MarmotMarkdownInline,
    pub inlines_len: usize,
}

impl From<MarkdownTableCellFfi> for MarmotMarkdownTableCell {
    fn from(value: MarkdownTableCellFfi) -> Self {
        let (inlines, inlines_len) = owned_inlines(value.inlines);
        Self {
            inlines,
            inlines_len,
        }
    }
}

impl CFree for MarmotMarkdownTableCell {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.inlines, self.inlines_len) };
    }
}

/// One table body row (mirror of one `Vec<TableCell>` inside `rows`).
#[repr(C)]
pub struct MarmotMarkdownTableRow {
    pub cells: *mut MarmotMarkdownTableCell,
    pub cells_len: usize,
}

impl From<Vec<MarkdownTableCellFfi>> for MarmotMarkdownTableRow {
    fn from(value: Vec<MarkdownTableCellFfi>) -> Self {
        let (cells, cells_len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { cells, cells_len }
    }
}

impl CFree for MarmotMarkdownTableRow {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.cells, self.cells_len) };
    }
}

/// One inline-level Markdown node. Child inlines are owned `(ptr, len)`
/// arrays freed by the parent.
#[repr(C)]
pub enum MarmotMarkdownInline {
    Text {
        content: *mut c_char,
    },
    SoftBreak,
    HardBreak,
    Code {
        content: *mut c_char,
    },
    Emph {
        children: *mut MarmotMarkdownInline,
        children_len: usize,
    },
    Strong {
        children: *mut MarmotMarkdownInline,
        children_len: usize,
    },
    Strikethrough {
        children: *mut MarmotMarkdownInline,
        children_len: usize,
    },
    Link {
        dest: *mut c_char,
        /// Nullable.
        title: *mut c_char,
        children: *mut MarmotMarkdownInline,
        children_len: usize,
    },
    Image {
        dest: *mut c_char,
        /// Nullable.
        title: *mut c_char,
        alt: *mut MarmotMarkdownInline,
        alt_len: usize,
    },
    Autolink {
        url: *mut c_char,
        kind: MarmotMarkdownAutolinkKind,
    },
    Math {
        content: *mut c_char,
    },
    NostrMention {
        entity: MarmotMarkdownNostrEntity,
    },
    NostrUri {
        entity: MarmotMarkdownNostrEntity,
    },
}

impl From<MarkdownInlineFfi> for MarmotMarkdownInline {
    fn from(value: MarkdownInlineFfi) -> Self {
        match value {
            MarkdownInlineFfi::Text { content } => Self::Text {
                content: owned_c_string(content),
            },
            MarkdownInlineFfi::SoftBreak => Self::SoftBreak,
            MarkdownInlineFfi::HardBreak => Self::HardBreak,
            MarkdownInlineFfi::Code { content } => Self::Code {
                content: owned_c_string(content),
            },
            MarkdownInlineFfi::Emph { children } => {
                let (children, children_len) = owned_inlines(children);
                Self::Emph {
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Strong { children } => {
                let (children, children_len) = owned_inlines(children);
                Self::Strong {
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Strikethrough { children } => {
                let (children, children_len) = owned_inlines(children);
                Self::Strikethrough {
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Link {
                dest,
                title,
                children,
            } => {
                let (children, children_len) = owned_inlines(children);
                Self::Link {
                    dest: owned_c_string(dest),
                    title: owned_opt_c_string(title),
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Image { dest, title, alt } => {
                let (alt, alt_len) = owned_inlines(alt);
                Self::Image {
                    dest: owned_c_string(dest),
                    title: owned_opt_c_string(title),
                    alt,
                    alt_len,
                }
            }
            MarkdownInlineFfi::Autolink { url, kind } => Self::Autolink {
                url: owned_c_string(url),
                kind: kind.into(),
            },
            MarkdownInlineFfi::Math { content } => Self::Math {
                content: owned_c_string(content),
            },
            MarkdownInlineFfi::NostrMention { entity } => Self::NostrMention {
                entity: entity.into(),
            },
            MarkdownInlineFfi::NostrUri { entity } => Self::NostrUri {
                entity: entity.into(),
            },
        }
    }
}

impl CFree for MarmotMarkdownInline {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Text { content } | Self::Code { content } | Self::Math { content } => unsafe {
                free_c_string(*content);
            },
            Self::SoftBreak | Self::HardBreak => {}
            Self::Emph {
                children,
                children_len,
            }
            | Self::Strong {
                children,
                children_len,
            }
            | Self::Strikethrough {
                children,
                children_len,
            } => unsafe { free_vec(*children, *children_len) },
            Self::Link {
                dest,
                title,
                children,
                children_len,
            } => unsafe {
                free_c_string(*dest);
                free_c_string(*title);
                free_vec(*children, *children_len);
            },
            Self::Image {
                dest,
                title,
                alt,
                alt_len,
            } => unsafe {
                free_c_string(*dest);
                free_c_string(*title);
                free_vec(*alt, *alt_len);
            },
            Self::Autolink { url, .. } => unsafe { free_c_string(*url) },
            Self::NostrMention { entity } | Self::NostrUri { entity } => unsafe {
                entity.free_in_place();
            },
        }
    }
}

/// Flavor of an autolink.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotMarkdownAutolinkKind {
    Uri,
    Email,
}

impl From<MarkdownAutolinkKindFfi> for MarmotMarkdownAutolinkKind {
    fn from(value: MarkdownAutolinkKindFfi) -> Self {
        match value {
            MarkdownAutolinkKindFfi::Uri => Self::Uri,
            MarkdownAutolinkKindFfi::Email => Self::Email,
        }
    }
}

impl CFree for MarmotMarkdownAutolinkKind {
    unsafe fn free_in_place(&mut self) {}
}

/// A recognized Nostr entity reference inside message text.
#[repr(C)]
pub struct MarmotMarkdownNostrEntity {
    pub hrp: MarmotMarkdownNostrHrp,
    pub bech32: *mut c_char,
}

impl From<MarkdownNostrEntityFfi> for MarmotMarkdownNostrEntity {
    fn from(value: MarkdownNostrEntityFfi) -> Self {
        Self {
            hrp: value.hrp.into(),
            bech32: owned_c_string(value.bech32),
        }
    }
}

impl CFree for MarmotMarkdownNostrEntity {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(self.bech32) };
    }
}

/// Human-readable prefix of a bech32 Nostr entity.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotMarkdownNostrHrp {
    Npub,
    Note,
    Nevent,
    Nprofile,
    Naddr,
    Nrelay,
}

impl From<MarkdownNostrHrpFfi> for MarmotMarkdownNostrHrp {
    fn from(value: MarkdownNostrHrpFfi) -> Self {
        match value {
            MarkdownNostrHrpFfi::Npub => Self::Npub,
            MarkdownNostrHrpFfi::Note => Self::Note,
            MarkdownNostrHrpFfi::Nevent => Self::Nevent,
            MarkdownNostrHrpFfi::Nprofile => Self::Nprofile,
            MarkdownNostrHrpFfi::Naddr => Self::Naddr,
            MarkdownNostrHrpFfi::Nrelay => Self::Nrelay,
        }
    }
}

impl CFree for MarmotMarkdownNostrHrp {
    unsafe fn free_in_place(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    fn c_str_eq(ptr: *mut c_char, expected: &str) -> bool {
        assert!(!ptr.is_null());
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid UTF-8")
            == expected
    }

    fn text(content: &str) -> MarkdownInlineFfi {
        MarkdownInlineFfi::Text {
            content: content.into(),
        }
    }

    fn slice<'a, T>(ptr: *mut T, len: usize) -> &'a [T] {
        assert!(!ptr.is_null());
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    fn sample_document() -> MarkdownDocumentFfi {
        MarkdownDocumentFfi {
            blocks: vec![
                MarkdownBlockFfi::Heading {
                    level: 2,
                    inlines: vec![text("Burrow notes")],
                },
                MarkdownBlockFfi::Paragraph {
                    inlines: vec![
                        MarkdownInlineFfi::Link {
                            dest: "https://example.com".into(),
                            title: Some("example".into()),
                            children: vec![text("site")],
                        },
                        MarkdownInlineFfi::NostrMention {
                            entity: MarkdownNostrEntityFfi {
                                hrp: MarkdownNostrHrpFfi::Npub,
                                bech32: "npub1abc".into(),
                            },
                        },
                        MarkdownInlineFfi::Code {
                            content: "cargo test".into(),
                        },
                    ],
                },
                MarkdownBlockFfi::ListBlock {
                    kind: MarkdownListKindFfi::Bullet { marker: "-".into() },
                    tight: true,
                    items: vec![MarkdownListItemFfi {
                        blocks: vec![
                            MarkdownBlockFfi::Paragraph {
                                inlines: vec![text("dig tunnel")],
                            },
                            MarkdownBlockFfi::ListBlock {
                                kind: MarkdownListKindFfi::Ordered {
                                    start: 3,
                                    delimiter: ".".into(),
                                },
                                tight: false,
                                items: vec![MarkdownListItemFfi {
                                    blocks: vec![MarkdownBlockFfi::Paragraph {
                                        inlines: vec![text("reinforce walls")],
                                    }],
                                    checked: Some(true),
                                }],
                            },
                        ],
                        checked: None,
                    }],
                },
                MarkdownBlockFfi::Table {
                    alignments: vec![MarkdownAlignmentFfi::Left, MarkdownAlignmentFfi::Right],
                    header: vec![
                        MarkdownTableCellFfi {
                            inlines: vec![text("a")],
                        },
                        MarkdownTableCellFfi {
                            inlines: vec![text("b")],
                        },
                    ],
                    rows: vec![vec![
                        MarkdownTableCellFfi {
                            inlines: vec![text("1")],
                        },
                        MarkdownTableCellFfi {
                            inlines: vec![text("2")],
                        },
                    ]],
                },
                MarkdownBlockFfi::CodeBlock {
                    kind: MarkdownCodeBlockKindFfi::Fenced,
                    info: "rust".into(),
                    content: "fn main() {}".into(),
                },
            ],
            truncated: true,
        }
    }

    #[test]
    fn document_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotMarkdownDocument = sample_document().into();
        assert!(mirror.truncated);
        let blocks = slice(mirror.blocks, mirror.blocks_len);
        assert_eq!(blocks.len(), 5);

        let MarmotMarkdownBlock::Heading {
            level,
            inlines,
            inlines_len,
        } = &blocks[0]
        else {
            panic!("expected heading");
        };
        assert_eq!(*level, 2);
        let heading_inlines = slice(*inlines, *inlines_len);
        let MarmotMarkdownInline::Text { content } = &heading_inlines[0] else {
            panic!("expected text");
        };
        assert!(c_str_eq(*content, "Burrow notes"));

        let MarmotMarkdownBlock::Paragraph {
            inlines,
            inlines_len,
        } = &blocks[1]
        else {
            panic!("expected paragraph");
        };
        let para = slice(*inlines, *inlines_len);
        let MarmotMarkdownInline::Link {
            dest,
            title,
            children,
            children_len,
        } = &para[0]
        else {
            panic!("expected link");
        };
        assert!(c_str_eq(*dest, "https://example.com"));
        assert!(c_str_eq(*title, "example"));
        let link_children = slice(*children, *children_len);
        assert!(matches!(
            link_children[0],
            MarmotMarkdownInline::Text { .. }
        ));
        let MarmotMarkdownInline::NostrMention { entity } = &para[1] else {
            panic!("expected nostr mention");
        };
        assert_eq!(entity.hrp, MarmotMarkdownNostrHrp::Npub);
        assert!(c_str_eq(entity.bech32, "npub1abc"));
        let MarmotMarkdownInline::Code { content } = &para[2] else {
            panic!("expected code span");
        };
        assert!(c_str_eq(*content, "cargo test"));

        let MarmotMarkdownBlock::ListBlock {
            kind,
            tight,
            items,
            items_len,
        } = &blocks[2]
        else {
            panic!("expected list");
        };
        assert!(*tight);
        let MarmotMarkdownListKind::Bullet { marker } = kind else {
            panic!("expected bullet kind");
        };
        assert!(c_str_eq(*marker, "-"));
        let items = slice(*items, *items_len);
        assert!(!items[0].has_checked);
        let item_blocks = slice(items[0].blocks, items[0].blocks_len);
        let MarmotMarkdownBlock::ListBlock {
            kind,
            items,
            items_len,
            ..
        } = &item_blocks[1]
        else {
            panic!("expected nested list");
        };
        let MarmotMarkdownListKind::Ordered {
            start: ordered_start,
            delimiter,
        } = kind
        else {
            panic!("expected ordered kind");
        };
        assert_eq!(*ordered_start, 3);
        assert!(c_str_eq(*delimiter, "."));
        let nested_items = slice(*items, *items_len);
        assert!(nested_items[0].has_checked);
        assert!(nested_items[0].checked);

        let MarmotMarkdownBlock::Table {
            alignments,
            alignments_len,
            header,
            header_len,
            rows,
            rows_len,
        } = &blocks[3]
        else {
            panic!("expected table");
        };
        assert_eq!(
            slice(*alignments, *alignments_len),
            [
                MarmotMarkdownAlignment::Left,
                MarmotMarkdownAlignment::Right
            ]
        );
        assert_eq!(*header_len, 2);
        assert!(!header.is_null());
        let rows = slice(*rows, *rows_len);
        assert_eq!(rows.len(), 1);
        let cells = slice(rows[0].cells, rows[0].cells_len);
        assert_eq!(cells.len(), 2);
        let cell_inlines = slice(cells[1].inlines, cells[1].inlines_len);
        let MarmotMarkdownInline::Text { content } = &cell_inlines[0] else {
            panic!("expected cell text");
        };
        assert!(c_str_eq(*content, "2"));

        let MarmotMarkdownBlock::CodeBlock {
            kind,
            info,
            content,
        } = &blocks[4]
        else {
            panic!("expected code block");
        };
        assert_eq!(*kind, MarmotMarkdownCodeBlockKind::Fenced);
        assert!(c_str_eq(*info, "rust"));
        assert!(c_str_eq(*content, "fn main() {}"));

        let root = boxed(mirror);
        unsafe { marmot_markdown_document_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn inline_variants_roundtrip_including_nested_emphasis() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let inlines = vec![
            MarkdownInlineFfi::Emph {
                children: vec![MarkdownInlineFfi::Strong {
                    children: vec![text("deep")],
                }],
            },
            MarkdownInlineFfi::Autolink {
                url: "https://marmot.example".into(),
                kind: MarkdownAutolinkKindFfi::Uri,
            },
            MarkdownInlineFfi::Image {
                dest: "https://example.com/m.png".into(),
                title: None,
                alt: vec![text("marmot")],
            },
            MarkdownInlineFfi::Strikethrough {
                children: vec![text("gone")],
            },
            MarkdownInlineFfi::HardBreak,
            MarkdownInlineFfi::Math {
                content: "e = mc^2".into(),
            },
        ];
        let mirror: MarmotMarkdownDocument = MarkdownDocumentFfi {
            blocks: vec![MarkdownBlockFfi::Paragraph { inlines }],
            truncated: false,
        }
        .into();

        let blocks = slice(mirror.blocks, mirror.blocks_len);
        let MarmotMarkdownBlock::Paragraph {
            inlines,
            inlines_len,
        } = &blocks[0]
        else {
            panic!("expected paragraph");
        };
        let para = slice(*inlines, *inlines_len);

        let MarmotMarkdownInline::Emph {
            children,
            children_len,
        } = &para[0]
        else {
            panic!("expected emph");
        };
        let emph_children = slice(*children, *children_len);
        let MarmotMarkdownInline::Strong {
            children,
            children_len,
        } = &emph_children[0]
        else {
            panic!("expected strong inside emph");
        };
        let strong_children = slice(*children, *children_len);
        let MarmotMarkdownInline::Text { content } = &strong_children[0] else {
            panic!("expected text inside strong");
        };
        assert!(c_str_eq(*content, "deep"));

        let MarmotMarkdownInline::Autolink { url, kind } = &para[1] else {
            panic!("expected autolink");
        };
        assert!(c_str_eq(*url, "https://marmot.example"));
        assert_eq!(*kind, MarmotMarkdownAutolinkKind::Uri);

        let MarmotMarkdownInline::Image {
            dest,
            title,
            alt,
            alt_len,
        } = &para[2]
        else {
            panic!("expected image");
        };
        assert!(c_str_eq(*dest, "https://example.com/m.png"));
        assert!(title.is_null());
        assert_eq!(slice(*alt, *alt_len).len(), 1);

        assert!(matches!(
            para[3],
            MarmotMarkdownInline::Strikethrough { .. }
        ));
        assert!(matches!(para[4], MarmotMarkdownInline::HardBreak));
        let MarmotMarkdownInline::Math { content } = &para[5] else {
            panic!("expected math");
        };
        assert!(c_str_eq(*content, "e = mc^2"));

        let root = boxed(mirror);
        unsafe { marmot_markdown_document_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_document_and_none_fields_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let mirror: MarmotMarkdownDocument = MarkdownDocumentFfi {
            blocks: Vec::new(),
            truncated: false,
        }
        .into();
        assert!(mirror.blocks.is_null());
        assert_eq!(mirror.blocks_len, 0);
        assert!(!mirror.truncated);
        let root = boxed(mirror);
        unsafe { marmot_markdown_document_free(root) };

        let mut link: MarmotMarkdownInline = MarkdownInlineFfi::Link {
            dest: "https://example.com".into(),
            title: None,
            children: Vec::new(),
        }
        .into();
        let MarmotMarkdownInline::Link {
            title,
            children,
            children_len,
            ..
        } = &link
        else {
            panic!("expected link");
        };
        assert!(title.is_null());
        assert!(children.is_null());
        assert_eq!(*children_len, 0);
        unsafe { link.free_in_place() };
    }
}
