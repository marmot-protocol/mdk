//! CommonMark and Nostr-aware Markdown parsing with an Odin core.
//!
//! The Rust layer exposes an owned, serde-friendly AST. Parsing and untrusted
//! destination classification run in Odin; the private native bridge copies the
//! result into Rust-owned values before releasing the per-parse arena.
//!
//! ## Architecture
//!
//! Two separate passes: block structure first, then inline tokenization and
//! reference resolution. The implementation lives in `odin/block.odin` and
//! `odin/inline.odin`; `odin/details.odin` handles bounded disclosures.
//!
//! ## HTML is not parsed
//!
//! General HTML blocks and inlines remain literal text. Renderers must escape
//! them. Autolinks, local-time timestamps and bounded `<details>` / `<summary>`
//! disclosures have structured AST representations.
//!
//! ## Untrusted destinations
//!
//! Link, image and autolink destinations are preserved and annotated with
//! [`LinkDestinationKind`]. Classification does not authorize navigation or
//! fetching: clients apply their own navigation, privacy and network policy.
//! Dangerous and sensitive destinations should remain inert by default.
//!
//! ```
//! use marmot_markdown::{Block, parse};
//!
//! let doc = parse("# Hi *there*");
//! assert!(matches!(doc.blocks.as_slice(), [Block::Heading { level: 1, .. }]));
//! ```
//!
//! All AST types implement `Serialize` and `Deserialize` unconditionally.

pub use marmot_markdown_ast as ast;
#[allow(unsafe_code)]
mod native;

/// Maximum nested block-container depth emitted by the parser.
pub const MAX_CONTAINER_DEPTH: usize = 96;

/// Maximum blank-line source gap retained before a block.
pub const MAX_SOURCE_BLANK_LINES: u8 = 8;

pub use ast::{
    Alignment, AutolinkKind, Block, CodeBlockKind, Document, Inline, LinkDestinationKind, ListItem,
    ListKind, NostrEntity, NostrHrp, TableCell, TimestampStyle,
};

/// Classify an untrusted destination without rewriting or removing it.
///
/// This classification is input to renderer policy, not permission to open or
/// fetch a destination. Keep dangerous and sensitive destinations inert unless
/// the client explicitly permits them.
pub fn classify_link_destination(destination: &str) -> LinkDestinationKind {
    native::classify(destination)
}

/// Parse CommonMark 0.31 with Marmot's display extensions into an owned AST.
///
/// Extensions include GFM tables, strikethrough and task lists; opaque inline
/// and block math; device-local timestamps; bounded disclosures; and Nostr
/// references. General HTML stays literal.
///
/// Bare URL schemes are `http://`, `https://`, `mailto:`, `tel:`, `marmot://`,
/// `whitenoise://` and `whitenoise-staging://`, plus `www.` forms. Trailing
/// punctuation and unbalanced closing parentheses are excluded. Opaque app
/// scheme forms without `//` remain literal.
///
/// Timestamp styles are `t`, `T`, `d`, `D`, `f`, `F`, `s`, `S` and `R`, with
/// omitted style defaulting to `f`. Timestamps retain signed Unix seconds;
/// locale, timezone and relative-time updates belong to renderers.
///
/// Disclosure recognition is limited to a UTF-8-safe 65536-byte original-source
/// prefix and a 4096-byte structural tag cap. Openers and closers occupy their
/// own logical lines. Missing or empty summaries produce an empty summary;
/// failed candidates fall back to ordinary Markdown without discarding text.
///
/// Nostr HRPs are `npub`, `note`, `nevent`, `nprofile`, `naddr` and `nrelay`.
/// [`Inline::NostrUri`] covers `nostr:` URIs and checksum-valid bare `note`,
/// `nevent` and `naddr` references. Bare `npub` mentions and prefixed URIs check
/// shape only; recognition does not validate event payloads. Private-key entities never
/// become ergonomic Nostr references; explicit destinations containing them
/// are preserved with [`LinkDestinationKind::Sensitive`].
pub fn parse(input: &str) -> Document {
    native::parse(input)
}
