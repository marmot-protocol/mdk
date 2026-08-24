//! C mirrors of the app-message Markdown display tree.
//!
//! The tree is recursive (blocks contain blocks and inlines; inlines
//! contain inlines), so the enums-with-payload mirrors and their
//! deep-frees are written by hand; the plain records still come from the
//! macros. C renders the enums as tag + union per cbindgen's tagged-enum
//! layout.

use std::ffi::c_char;

use marmot_uniffi::{
    MarkdownAlignmentFfi, MarkdownAutolinkKindFfi, MarkdownBlockFfi, MarkdownCodeBlockKindFfi,
    MarkdownDocumentFfi, MarkdownInlineFfi, MarkdownLinkDestinationKindFfi, MarkdownListItemFfi,
    MarkdownListKindFfi, MarkdownNostrEntityFfi, MarkdownNostrHrpFfi, MarkdownTableCellFfi,
};

use crate::macros::{c_enum, c_mirror};
use crate::memory::{
    CFree, free_c_string, free_vec, owned_c_string, owned_opt_c_string, owned_vec,
};

c_enum! {
    /// How a fenced/indented code block was written.
    MarmotMarkdownCodeBlockKind from MarkdownCodeBlockKindFfi {
        Indented,
        Fenced,
    }
}

c_enum! {
    /// Table column alignment.
    MarmotMarkdownAlignment from MarkdownAlignmentFfi {
        None,
        Left,
        Center,
        Right,
    }
}

c_enum! {
    /// Autolink flavor.
    MarmotMarkdownAutolinkKind from MarkdownAutolinkKindFfi {
        Uri,
        Email,
        /// Bare `www.` host/path text. Hosts synthesize `https://`.
        Www,
    }
}

c_enum! {
    /// Safety classification of a link/image/autolink destination.
    MarmotMarkdownLinkDestinationKind from MarkdownLinkDestinationKindFfi {
        Web,
        Contact,
        App,
        Nostr,
        Relative,
        Unknown,
        Dangerous,
        Sensitive,
    }
}

c_enum! {
    /// Bech32 human-readable prefix of a Nostr entity.
    MarmotMarkdownNostrHrp from MarkdownNostrHrpFfi {
        Npub,
        Note,
        Nevent,
        Nprofile,
        Naddr,
        Nrelay,
    }
}

c_mirror! {
    /// One referenced Nostr entity.
    MarmotMarkdownNostrEntity from MarkdownNostrEntityFfi {
        copy hrp: MarmotMarkdownNostrHrp,
        str bech32,
    }
}

/// One inline Markdown node. Child arrays are owned by the parent; free
/// only the document root.
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
        classification: MarmotMarkdownLinkDestinationKind,
    },
    Image {
        dest: *mut c_char,
        /// Nullable.
        title: *mut c_char,
        alt: *mut MarmotMarkdownInline,
        alt_len: usize,
        classification: MarmotMarkdownLinkDestinationKind,
    },
    Autolink {
        url: *mut c_char,
        kind: MarmotMarkdownAutolinkKind,
        classification: MarmotMarkdownLinkDestinationKind,
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

fn inline_vec(children: Vec<MarkdownInlineFfi>) -> (*mut MarmotMarkdownInline, usize) {
    owned_vec(children.into_iter().map(Into::into).collect())
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
                let (children, children_len) = inline_vec(children);
                Self::Emph {
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Strong { children } => {
                let (children, children_len) = inline_vec(children);
                Self::Strong {
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Strikethrough { children } => {
                let (children, children_len) = inline_vec(children);
                Self::Strikethrough {
                    children,
                    children_len,
                }
            }
            MarkdownInlineFfi::Link {
                dest,
                title,
                children,
                classification,
            } => {
                let (children, children_len) = inline_vec(children);
                Self::Link {
                    dest: owned_c_string(dest),
                    title: owned_opt_c_string(title),
                    children,
                    children_len,
                    classification: classification.into(),
                }
            }
            MarkdownInlineFfi::Image {
                dest,
                title,
                alt,
                classification,
            } => {
                let (alt, alt_len) = inline_vec(alt);
                Self::Image {
                    dest: owned_c_string(dest),
                    title: owned_opt_c_string(title),
                    alt,
                    alt_len,
                    classification: classification.into(),
                }
            }
            MarkdownInlineFfi::Autolink {
                url,
                kind,
                classification,
            } => Self::Autolink {
                url: owned_c_string(url),
                kind: kind.into(),
                classification: classification.into(),
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
        unsafe {
            match self {
                Self::Text { content } | Self::Code { content } | Self::Math { content } => {
                    free_c_string(*content)
                }
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
                } => free_vec(*children, *children_len),
                Self::Link {
                    dest,
                    title,
                    children,
                    children_len,
                    ..
                } => {
                    free_c_string(*dest);
                    free_c_string(*title);
                    free_vec(*children, *children_len);
                }
                Self::Image {
                    dest,
                    title,
                    alt,
                    alt_len,
                    ..
                } => {
                    free_c_string(*dest);
                    free_c_string(*title);
                    free_vec(*alt, *alt_len);
                }
                Self::Autolink { url, .. } => free_c_string(*url),
                Self::NostrMention { entity } | Self::NostrUri { entity } => entity.free_in_place(),
            }
        }
    }
}

/// List flavor (bullet vs ordered).
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
        unsafe {
            match self {
                Self::Bullet { marker } => free_c_string(*marker),
                Self::Ordered { delimiter, .. } => free_c_string(*delimiter),
            }
        }
    }
}

/// One list item: nested blocks plus an optional task-list checkbox.
#[repr(C)]
pub struct MarmotMarkdownListItem {
    pub blocks: *mut MarmotMarkdownBlock,
    pub blocks_len: usize,
    /// Task-list state: unset for plain items.
    pub has_checked: bool,
    pub checked: bool,
    /// Blank source lines before each corresponding child block.
    pub blank_lines_before: *mut u8,
    pub blank_lines_before_len: usize,
}

impl From<MarkdownListItemFfi> for MarmotMarkdownListItem {
    fn from(value: MarkdownListItemFfi) -> Self {
        let (blocks, blocks_len) = block_vec(value.blocks);
        let (blank_lines_before, blank_lines_before_len) = owned_vec(value.blank_lines_before);
        Self {
            blocks,
            blocks_len,
            has_checked: value.checked.is_some(),
            checked: value.checked.unwrap_or_default(),
            blank_lines_before,
            blank_lines_before_len,
        }
    }
}

impl CFree for MarmotMarkdownListItem {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.blocks, self.blocks_len);
            free_vec(self.blank_lines_before, self.blank_lines_before_len);
        }
    }
}

c_mirror! {
    /// One table cell.
    MarmotMarkdownTableCell from MarkdownTableCellFfi {
        vec inlines/inlines_len: MarmotMarkdownInline,
    }
}

/// One table body row.
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

/// One block-level Markdown node.
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
        /// Blank source lines before each corresponding child block.
        blank_lines_before: *mut u8,
        blank_lines_before_len: usize,
    },
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

fn block_vec(blocks: Vec<MarkdownBlockFfi>) -> (*mut MarmotMarkdownBlock, usize) {
    owned_vec(blocks.into_iter().map(Into::into).collect())
}

impl From<MarkdownBlockFfi> for MarmotMarkdownBlock {
    fn from(value: MarkdownBlockFfi) -> Self {
        match value {
            MarkdownBlockFfi::Paragraph { inlines } => {
                let (inlines, inlines_len) = inline_vec(inlines);
                Self::Paragraph {
                    inlines,
                    inlines_len,
                }
            }
            MarkdownBlockFfi::Heading { level, inlines } => {
                let (inlines, inlines_len) = inline_vec(inlines);
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
            MarkdownBlockFfi::BlockQuote {
                blocks,
                blank_lines_before,
            } => {
                let (blocks, blocks_len) = block_vec(blocks);
                let (blank_lines_before, blank_lines_before_len) = owned_vec(blank_lines_before);
                Self::BlockQuote {
                    blocks,
                    blocks_len,
                    blank_lines_before,
                    blank_lines_before_len,
                }
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
        unsafe {
            match self {
                Self::Paragraph {
                    inlines,
                    inlines_len,
                }
                | Self::Heading {
                    inlines,
                    inlines_len,
                    ..
                } => free_vec(*inlines, *inlines_len),
                Self::ThematicBreak => {}
                Self::CodeBlock { info, content, .. } => {
                    free_c_string(*info);
                    free_c_string(*content);
                }
                Self::BlockQuote {
                    blocks,
                    blocks_len,
                    blank_lines_before,
                    blank_lines_before_len,
                } => {
                    free_vec(*blocks, *blocks_len);
                    free_vec(*blank_lines_before, *blank_lines_before_len);
                }
                Self::ListBlock {
                    kind,
                    items,
                    items_len,
                    ..
                } => {
                    kind.free_in_place();
                    free_vec(*items, *items_len);
                }
                Self::Table {
                    alignments,
                    alignments_len,
                    header,
                    header_len,
                    rows,
                    rows_len,
                } => {
                    free_vec(*alignments, *alignments_len);
                    free_vec(*header, *header_len);
                    free_vec(*rows, *rows_len);
                }
                Self::MathBlock { content } => free_c_string(*content),
            }
        }
    }
}

c_mirror! {
    /// A parsed Markdown display document.
    MarmotMarkdownDocument from MarkdownDocumentFfi,
    free marmot_markdown_document_free {
        vec blocks/blocks_len: MarmotMarkdownBlock,
        /// True when the input exceeded the FFI Markdown safety cap and
        /// `blocks` were parsed from a UTF-8-boundary prefix.
        copy truncated: bool,
        /// Blank source lines before each corresponding block.
        prim_vec blank_lines_before/blank_lines_before_len: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    // The recursive tagged-union free path is the one place a leak can
    // hide structurally; walk a document exercising every container kind.
    #[test]
    fn nested_document_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let doc = MarkdownDocumentFfi {
            blocks: vec![
                MarkdownBlockFfi::Heading {
                    level: 2,
                    inlines: vec![MarkdownInlineFfi::Strong {
                        children: vec![MarkdownInlineFfi::Text {
                            content: "hi".into(),
                        }],
                    }],
                },
                MarkdownBlockFfi::BlockQuote {
                    blocks: vec![MarkdownBlockFfi::ListBlock {
                        kind: MarkdownListKindFfi::Ordered {
                            start: 3,
                            delimiter: ".".into(),
                        },
                        tight: true,
                        items: vec![MarkdownListItemFfi {
                            blocks: vec![MarkdownBlockFfi::Paragraph {
                                inlines: vec![MarkdownInlineFfi::Link {
                                    dest: "https://example.test".into(),
                                    title: None,
                                    children: vec![MarkdownInlineFfi::Code {
                                        content: "x".into(),
                                    }],
                                    classification: MarkdownLinkDestinationKindFfi::Web,
                                }],
                            }],
                            checked: Some(true),
                            blank_lines_before: vec![0],
                        }],
                    }],
                    blank_lines_before: vec![1],
                },
                MarkdownBlockFfi::Table {
                    alignments: vec![MarkdownAlignmentFfi::Left],
                    header: vec![MarkdownTableCellFfi {
                        inlines: vec![MarkdownInlineFfi::Text {
                            content: "h".into(),
                        }],
                    }],
                    rows: vec![vec![MarkdownTableCellFfi {
                        inlines: vec![MarkdownInlineFfi::NostrMention {
                            entity: MarkdownNostrEntityFfi {
                                hrp: MarkdownNostrHrpFfi::Npub,
                                bech32: "npub1xyz".into(),
                            },
                        }],
                    }]],
                },
            ],
            truncated: false,
            blank_lines_before: vec![0, 1, 0],
        };

        let mirror: MarmotMarkdownDocument = doc.into();
        assert_eq!(mirror.blocks_len, 3);
        let root = boxed(mirror);
        unsafe { marmot_markdown_document_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
