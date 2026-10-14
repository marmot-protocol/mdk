# marmot-markdown

CommonMark and Nostr-aware display parser for Marmot app messages. It turns plaintext message content into a typed,
serde-friendly AST that CLI, TUI, and mobile renderers draw from. It does not define wire format, persistence, or CGKA
engine behavior.

## What this crate does

- Parses CommonMark plus GFM-style tables and strikethrough, math, and a bounded `<details>` extension into `Block` /
  `Inline` nodes.
- Recognizes Nostr entities inline: bare `@npub1…` handles (`Inline::NostrMention`) and explicit `nostr:<hrp>1…`
  references (`Inline::NostrUri`), and classifies private-key destinations as sensitive.
- Parses local-time timestamps into `Inline::Timestamp` with Unix seconds and a typed display style.
- Does not parse general HTML. Tag-like sequences stay literal text; only autolinks, timestamps and the `<details>` extension get
  structured treatment.
- Keeps dependencies minimal (`serde` only in normal builds).

```rust
use marmot_markdown::{Block, parse};

let doc = parse("# Hi *there*");
assert!(matches!(doc.blocks.as_slice(), [Block::Heading { level: 1, .. }]));
```

## Renderer security contract

Message Markdown and every link destination are untrusted. The parser preserves destinations instead of deleting or
rewriting them, and annotates links, images, and autolinks with `LinkDestinationKind`. That classification is context
for client policy; it is not authorization to navigate or fetch.

Renderers **must inspect `classification` before making a destination actionable**. In particular:

- `Dangerous` (`javascript:`, `data:`, `vbscript:`, `file:`) and `Sensitive` (`nsec` / `ncryptsec`, including Nostr
  wrappers) should remain non-actionable by default.
- `Unknown` and `Relative` require an explicit client decision rather than inheriting a WebView or OS opener default.
- `Web`, `Contact`, `App`, and `Nostr` identify recognized destination families, but clients still apply their own
  navigation, deep-link, privacy, and network policies.
- Image renderers must apply the classification and their network policy before fetching `dest`; classification alone
  does not establish that a host or resolved address is safe.

The same classification is present on the MarmotKit/UniFFI Markdown types. Clients may still display the original
destination or link text when policy keeps it inert.

## What it does not do

- No CGKA engine, storage, transport, or runtime state.
- No UniFFI surface of its own (bindings expose parsed output through `marmot-app` / `marmot-uniffi` as needed).

## Bounded details/summary disclosures

The parser recognizes structural `<details>` / `<summary>` lines as `Block::Details`.
This is a block-oriented extension, not a general HTML parser:

- The opening `<details ...>` and closing `</details>` each occupy their own
  logical line after quote/list prefixes and at most three columns of local
  indent. Surrounding horizontal whitespace is allowed. Compact one-line HTML
  such as `<details><summary>x</summary>y</details>` stays literal text.
- An optional first nonblank `<summary ...>...</summary>` child is inline-parsed
  (formatting, entities, links, and Nostr mentions). Missing or empty summaries
  yield `summary: []`; clients may supply a localized fallback label. A later
  summary is ordinary body text. A malformed initial summary falls back to
  ordinary Markdown instead of dropping text.
- The `open` attribute means expanded even when written `open="false"`. Other
  attributes are ignored and never tokenized as destinations. Styles, scripts,
  event handlers, and URLs are not rendering instructions.
- Recognition uses original source before entity decoding. Escaped
  (`\<details>`, `&lt;details&gt;`), inline-code, fenced/indented code, and math
  forms stay literal. Failed or unclosed candidates keep their tags as ordinary
  Markdown and do not swallow following siblings.
- Recognition is limited to a 65536-byte original-source prefix and a 4096-byte
  structural tag cap (inclusive of `<` through `>`). Each details block consumes
  one existing container-depth slot. Recognition work is linear in that capped
  prefix: each continuation line is scanned once with carried code-span state,
  and unmatched backtick runs are never rescanned. An open summary code span
  keeps interior `</summary>` and `</details>` lines as content until a
  matching run closes it. Failed candidates restore ordinary block structure
  and source gaps instead of collapsing to one paragraph.
- Body blank-line counts align with `body` and saturate at
  `MAX_SOURCE_BLANK_LINES`. Delimiter-only lines are not blocks. Blanks before
  the closer stay inside the disclosure.

## Device-local timestamps

`<t:1791280800:F>` produces `Timestamp { unix_seconds: 1791280800, style: LongDateTime }`.
The instant stays unchanged when the user travels. The renderer formats it using the device's current timezone and
locale, including daylight-saving rules at that instant.

Timestamp syntax uses seconds, not milliseconds. These case-sensitive styles are supported:

| Style | AST style | Display |
| --- | --- | --- |
| `t` | `ShortTime` | Hours and minutes |
| `T` | `LongTime` | Hours, minutes and seconds |
| `d` | `ShortDate` | Numeric date |
| `D` | `LongDate` | Long date with a month name |
| `f` (default) | `ShortDateTime` | Long date and short time |
| `F` | `LongDateTime` | Weekday, long date and short time |
| `s` | `CompactDateTime` | Numeric date and short time |
| `S` | `CompactDateTimeSeconds` | Numeric date and time including seconds |
| `R` | `Relative` | Live relative time, such as `in 30 minutes` or `2 hours ago` |

`<t:1791280800>` is equivalent to `<t:1791280800:f>`. Signed decimal `i64` seconds are accepted, including dates
before 1970. Unknown styles, overflow, whitespace inside a token, and malformed tokens remain literal text.
Escaped/entity-encoded tokens, code and math do not become timestamps. Timestamps can appear in formatted text,
link labels, headings, tables and details summaries.

The parser does not read a clock or cache a formatted string. Renderers must:

- Format absolute styles with current device locale, timezone and hour-cycle preferences.
- Reformat visible timestamps after timezone, locale or clock changes and on resume. Recreate cached formatters
  when their device settings change; reparsing the message is unnecessary.
- Refresh visible `Relative` nodes as time passes, in both past and future directions. Use the current clock each
  time; calendar phrases such as `next Monday` depend on the local calendar and locale.
- Provide an absolute local date/time for relative-node tooltips or accessibility descriptions.
- Keep out-of-range instants inert and readable if the platform formatter cannot represent them; do not crash or
  wrap seconds when converting to platform time units.

The AST and bindings provide the instant and style, not a timer or a UI widget. This repository does not contain
the mobile timestamp renderer.

## Run the tests

```sh
cargo test -p marmot-markdown
```

Golden fixtures under `tests/golden/` lock parser output. After an intentional output change, regenerate them with
`MARMOT_MD_UPDATE_GOLDEN=1 cargo test -p marmot-markdown --test golden`, review the diff, and re-run without the variable.

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
