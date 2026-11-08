//! Private C ABI. Odin owns the graph until it has been copied into the public AST.

use crate::ast::*;
use std::{marker::PhantomData, mem::MaybeUninit, slice};

const PARSE_SCRATCH_BYTES: usize = 16 * 1024;
#[repr(C, align(16))]
struct ParseScratch {
    _memory: [MaybeUninit<u8>; PARSE_SCRATCH_BYTES],
}

#[repr(C)]
struct NativeSlice<T> {
    data: *const T,
    len: usize,
}
impl<T> Copy for NativeSlice<T> {}
impl<T> Clone for NativeSlice<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> NativeSlice<T> {
    fn get(&self) -> &[T] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: Odin supplies aligned, initialized arena data. The parse handle
        // remains alive through conversion, including unwinding.
        unsafe { slice::from_raw_parts(self.data, self.len) }
    }
}
type NativeString = NativeSlice<u8>;
impl NativeString {
    fn owned(&self) -> String {
        // SAFETY: native strings are UTF-8 source spans, valid static entities,
        // or Unicode scalar encodings, never partial scalars.
        unsafe { String::from_utf8_unchecked(self.get().to_vec()) }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeDocument {
    blocks: NativeSlice<NativeBlock>,
    blank_lines_before: NativeSlice<u8>,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeListKind {
    tag: u32,
    marker: u8,
    start: u32,
    delimiter: u8,
}
#[repr(C)]
struct NativeListItem {
    blocks: NativeSlice<NativeBlock>,
    blank_lines_before: NativeSlice<u8>,
    checked: i32,
}
#[repr(C)]
struct NativeTableCell {
    inlines: NativeSlice<NativeInline>,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeCode {
    info: NativeString,
    content: NativeString,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeList {
    kind: NativeListKind,
    tight: u8,
    items: NativeSlice<NativeListItem>,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeTable {
    alignments: NativeSlice<u32>,
    header: NativeSlice<NativeTableCell>,
    rows: NativeSlice<NativeSlice<NativeTableCell>>,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeDetails {
    summary: NativeSlice<NativeInline>,
    open: u8,
    body: NativeSlice<NativeBlock>,
    blank_lines_before: NativeSlice<u8>,
}
#[repr(C)]
union NativeBlockData {
    inlines: NativeSlice<NativeInline>,
    code: NativeCode,
    quote: NativeDocument,
    list: NativeList,
    table: NativeTable,
    math: NativeString,
    details: NativeDetails,
}
#[repr(C)]
union NativeBlockMeta {
    level: u8,
    code_kind: u32,
}
#[repr(C)]
struct NativeBlock {
    tag: u32,
    meta: NativeBlockMeta,
    data: NativeBlockData,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeLink {
    dest: NativeString,
    title: NativeString,
    children: NativeSlice<NativeInline>,
}
#[repr(C)]
union NativeInlineData {
    text: NativeString,
    children: NativeSlice<NativeInline>,
    link: NativeLink,
    unix_seconds: i64,
}
#[repr(C)]
union NativeInlineAux {
    has_title: u8,
    autolink_kind: u32,
}
#[repr(C)]
struct NativeInline {
    tag: u32,
    meta: u32,
    aux: NativeInlineAux,
    data: NativeInlineData,
}

unsafe extern "C" {
    fn markdown_parse(
        data: *const u8,
        len: usize,
        scratch: *mut u8,
        capacity: usize,
    ) -> *mut NativeDocument;
    fn markdown_free(document: *mut NativeDocument);
    fn markdown_classify(data: *const u8, len: usize) -> u32;
}
struct ParseHandle<'a> {
    document: *mut NativeDocument,
    _borrow: PhantomData<(&'a str, &'a mut MaybeUninit<ParseScratch>)>,
}
impl<'a> ParseHandle<'a> {
    fn new(input: &'a str, scratch: &'a mut MaybeUninit<ParseScratch>) -> Self {
        // SAFETY: the handle borrows both buffers through graph conversion and
        // overflow cleanup. Odin initializes its header in aligned scratch.
        let document = unsafe {
            markdown_parse(
                input.as_ptr(),
                input.len(),
                scratch.as_mut_ptr().cast(),
                PARSE_SCRATCH_BYTES,
            )
        };
        Self {
            document,
            _borrow: PhantomData,
        }
    }
}
impl Drop for ParseHandle<'_> {
    fn drop(&mut self) {
        // SAFETY: the scratch frame is still alive; this releases only overflow blocks.
        unsafe { markdown_free(self.document) };
    }
}
pub(super) fn parse(input: &str) -> Document {
    let mut scratch = MaybeUninit::<ParseScratch>::uninit();
    let handle = ParseHandle::new(input, &mut scratch);
    // SAFETY: Odin returns the initialized document at the start of scratch.
    let native = unsafe { &*handle.document };
    Document {
        blocks: blocks(&native.blocks),
        blank_lines_before: native.blank_lines_before.get().to_vec(),
    }
}
pub(super) fn classify(destination: &str) -> LinkDestinationKind {
    // SAFETY: destination is valid for the duration of the native call.
    destination_kind(unsafe { markdown_classify(destination.as_ptr(), destination.len()) })
}
fn destination_kind(tag: u32) -> LinkDestinationKind {
    match tag {
        0 => LinkDestinationKind::Web,
        1 => LinkDestinationKind::Contact,
        2 => LinkDestinationKind::App,
        3 => LinkDestinationKind::Nostr,
        4 => LinkDestinationKind::Relative,
        5 => LinkDestinationKind::Unknown,
        6 => LinkDestinationKind::Dangerous,
        7 => LinkDestinationKind::Sensitive,
        _ => unreachable!("invalid native destination tag"),
    }
}
fn blocks(items: &NativeSlice<NativeBlock>) -> Vec<Block> {
    items.get().iter().map(block).collect()
}
fn inlines(items: &NativeSlice<NativeInline>) -> Vec<Inline> {
    items.get().iter().map(inline).collect()
}
fn cells(items: &NativeSlice<NativeTableCell>) -> Vec<TableCell> {
    items
        .get()
        .iter()
        .map(|cell| TableCell {
            inlines: inlines(&cell.inlines),
        })
        .collect()
}
fn block(item: &NativeBlock) -> Block {
    // SAFETY: each tag below selects precisely the active Odin raw-union field.
    unsafe {
        match item.tag {
            0 => Block::Paragraph {
                inlines: inlines(&item.data.inlines),
            },
            1 => Block::Heading {
                level: item.meta.level,
                inlines: inlines(&item.data.inlines),
            },
            2 => Block::ThematicBreak,
            3 => Block::CodeBlock {
                kind: match item.meta.code_kind {
                    0 => CodeBlockKind::Indented,
                    1 => CodeBlockKind::Fenced,
                    _ => unreachable!("invalid native code tag"),
                },
                info: item.data.code.info.owned(),
                content: item.data.code.content.owned(),
            },
            4 => Block::BlockQuote {
                blocks: blocks(&item.data.quote.blocks),
                blank_lines_before: item.data.quote.blank_lines_before.get().to_vec(),
            },
            5 => {
                let list = &item.data.list;
                Block::List {
                    kind: match list.kind.tag {
                        0 => ListKind::Bullet {
                            marker: list.kind.marker,
                        },
                        1 => ListKind::Ordered {
                            start: list.kind.start,
                            delimiter: list.kind.delimiter,
                        },
                        _ => unreachable!("invalid native list tag"),
                    },
                    tight: list.tight != 0,
                    items: list
                        .items
                        .get()
                        .iter()
                        .map(|child| ListItem {
                            blocks: blocks(&child.blocks),
                            blank_lines_before: child.blank_lines_before.get().to_vec(),
                            checked: match child.checked {
                                -1 => None,
                                0 => Some(false),
                                1 => Some(true),
                                _ => unreachable!("invalid native task state"),
                            },
                        })
                        .collect(),
                }
            }
            6 => {
                let table = &item.data.table;
                Block::Table {
                    alignments: table
                        .alignments
                        .get()
                        .iter()
                        .map(|tag| match tag {
                            0 => Alignment::None,
                            1 => Alignment::Left,
                            2 => Alignment::Center,
                            3 => Alignment::Right,
                            _ => unreachable!("invalid native alignment tag"),
                        })
                        .collect(),
                    header: cells(&table.header),
                    rows: table.rows.get().iter().map(cells).collect(),
                }
            }
            7 => Block::MathBlock {
                content: item.data.math.owned(),
            },
            8 => {
                let details = &item.data.details;
                Block::Details {
                    summary: inlines(&details.summary),
                    open: details.open != 0,
                    body: blocks(&details.body),
                    blank_lines_before: details.blank_lines_before.get().to_vec(),
                }
            }
            _ => unreachable!("invalid native block tag"),
        }
    }
}
fn inline(item: &NativeInline) -> Inline {
    // SAFETY: the producer's tag selects the active data/meta/aux union fields.
    unsafe {
        match item.tag {
            0 => Inline::Text(item.data.text.owned()),
            1 => Inline::SoftBreak,
            2 => Inline::HardBreak,
            3 => Inline::Code(item.data.text.owned()),
            4 => Inline::Emph(inlines(&item.data.children)),
            5 => Inline::Strong(inlines(&item.data.children)),
            6 => Inline::Strikethrough(inlines(&item.data.children)),
            7 => Inline::Link {
                dest: item.data.link.dest.owned(),
                title: (item.aux.has_title != 0).then(|| item.data.link.title.owned()),
                children: inlines(&item.data.link.children),
                classification: destination_kind(item.meta),
            },
            8 => Inline::Image {
                dest: item.data.link.dest.owned(),
                title: (item.aux.has_title != 0).then(|| item.data.link.title.owned()),
                alt: inlines(&item.data.link.children),
                classification: destination_kind(item.meta),
            },
            9 => Inline::Autolink {
                url: item.data.text.owned(),
                kind: match item.aux.autolink_kind {
                    0 => AutolinkKind::Uri,
                    1 => AutolinkKind::Email,
                    2 => AutolinkKind::Www,
                    _ => unreachable!("invalid native autolink tag"),
                },
                classification: destination_kind(item.meta),
            },
            10 => Inline::Math(item.data.text.owned()),
            11 | 12 => {
                let entity = NostrEntity {
                    hrp: match item.meta {
                        0 => NostrHrp::Npub,
                        1 => NostrHrp::Note,
                        2 => NostrHrp::Nevent,
                        3 => NostrHrp::Nprofile,
                        4 => NostrHrp::Naddr,
                        5 => NostrHrp::Nrelay,
                        _ => unreachable!("invalid native Nostr tag"),
                    },
                    bech32: item.data.text.owned(),
                };
                if item.tag == 11 {
                    Inline::NostrMention(entity)
                } else {
                    Inline::NostrUri(entity)
                }
            }
            13 => Inline::Timestamp {
                unix_seconds: item.data.unix_seconds,
                style: match item.meta {
                    0 => TimestampStyle::ShortTime,
                    1 => TimestampStyle::LongTime,
                    2 => TimestampStyle::ShortDate,
                    3 => TimestampStyle::LongDate,
                    4 => TimestampStyle::ShortDateTime,
                    5 => TimestampStyle::LongDateTime,
                    6 => TimestampStyle::CompactDateTime,
                    7 => TimestampStyle::CompactDateTimeSeconds,
                    8 => TimestampStyle::Relative,
                    _ => unreachable!("invalid native timestamp style"),
                },
            },
            _ => unreachable!("invalid native inline tag"),
        }
    }
}
