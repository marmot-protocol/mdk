package markdown

MAX_CONTAINER_DEPTH :: 96
MAX_SOURCE_BLANK_LINES :: 8
MAX_INLINE_NESTING_DEPTH :: 96

Document :: struct {
	blocks:             []Block,
	blank_lines_before: []u8,
}
BlockKind :: enum u32 {
	Paragraph,
	Heading,
	ThematicBreak,
	CodeBlock,
	BlockQuote,
	List,
	Table,
	MathBlock,
	Details,
}
CodeBlockKind :: enum u32 {
	Indented,
	Fenced,
}
ListTag :: enum u32 {
	Bullet,
	Ordered,
}
ListKind :: struct {
	tag:       ListTag,
	marker:    u8,
	start:     u32,
	delimiter: u8,
}
Alignment :: enum u32 {
	None,
	Left,
	Center,
	Right,
}
ListItem :: struct {
	blocks:             []Block,
	blank_lines_before: []u8,
	checked:            i32,
}
TableCell :: struct {
	inlines: []Inline,
}

CodePayload :: struct {
	info, content: string,
}
ChildPayload :: struct {
	blocks:             []Block,
	blank_lines_before: []u8,
}
ListPayload :: struct {
	kind:  ListKind,
	tight: bool,
	items: []ListItem,
}
TablePayload :: struct {
	alignments: []Alignment,
	header:     []TableCell,
	rows:       [][]TableCell,
}
DetailsPayload :: struct {
	summary:            []Inline,
	open:               bool,
	body:               []Block,
	blank_lines_before: []u8,
}
BlockMeta :: struct #raw_union {
	level:     u8,
	code_kind: CodeBlockKind,
}
BlockData :: struct #raw_union {
	inlines: []Inline,
	code:    CodePayload,
	quote:   ChildPayload,
	list:    ListPayload,
	table:   TablePayload,
	math:    string,
	details: DetailsPayload,
}
Block :: struct {
	tag:        BlockKind,
	using meta: BlockMeta,
	using data: BlockData,
}

InlineKind :: enum u32 {
	Text,
	SoftBreak,
	HardBreak,
	Code,
	Emph,
	Strong,
	Strikethrough,
	Link,
	Image,
	Autolink,
	Math,
	NostrMention,
	NostrUri,
	Timestamp,
}
AutolinkKind :: enum u32 {
	Uri,
	Email,
	Www,
}
LinkDestinationKind :: enum u32 {
	Web,
	Contact,
	App,
	Nostr,
	Relative,
	Unknown,
	Dangerous,
	Sensitive,
}
NostrHrp :: enum u32 {
	Npub,
	Note,
	Nevent,
	Nprofile,
	Naddr,
	Nrelay,
}
TimestampStyle :: enum u32 {
	ShortTime,
	LongTime,
	ShortDate,
	LongDate,
	ShortDateTime,
	LongDateTime,
	CompactDateTime,
	CompactDateTimeSeconds,
	Relative,
}
LinkPayload :: struct {
	dest, title: string,
	children:    []Inline,
}
InlineMeta :: struct #raw_union {
	classification: LinkDestinationKind,
	hrp:            NostrHrp,
	style:          TimestampStyle,
}
InlineAux :: struct #raw_union {
	has_title:     bool,
	autolink_kind: AutolinkKind,
}
InlineData :: struct #raw_union {
	text:         string,
	children:     []Inline,
	link:         LinkPayload,
	unix_seconds: i64,
}
Inline :: struct {
	tag:        InlineKind,
	using meta: InlineMeta,
	using aux:  InlineAux,
	using data: InlineData,
}
LinkRef :: struct {
	dest:      string,
	title:     string,
	has_title: bool,
}
