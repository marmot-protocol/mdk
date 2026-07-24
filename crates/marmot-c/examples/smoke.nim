# End-to-end smoke test for the marmot-c ABI from Nim.
#
# Nim compiles to C, so it pulls in the real marmot.h and lets the C compiler
# see the true declarations (importc + header). Struct layout and signatures
# are therefore the C compiler's, not hand-transcribed. This exercises the
# same realistic slice as examples/smoke.c: client lifecycle, the last-error
# and typed-error paths, a DEEP walk of the recursive Markdown DTO tree
# (block/inline tagged unions), offline reads, a directory lookup, and the
# best-effort identity publish — all behind an idiomatic Nim wrapper that
# raises `MarmotError` and frees via `=destroy`.
#
# Build & run (see c-smoke.sh for the canonical invocation):
#   nim c -d:release --nimcache:<tmp> \
#       --passC:"-I<crate>/include -Wno-incompatible-pointer-types" \
#       --passL:"<target>/debug/libmarmot_c.a -lm -lpthread -ldl" \
#       -o:smoke_nim examples/smoke.nim
#   ./smoke_nim <fresh-empty-home-dir>
#
# `-Wno-incompatible-pointer-types`: Nim models `cstring` as `char*` and has
# no `const`-pointee notion, so it emits `char**` where the header declares
# `const char *const *relay_urls`. gcc 14+ makes that const mismatch an error
# by default; it is benign for FFI, so we downgrade just that diagnostic.

import std/[os, options]

# The header include path (-I <crate>/include) and the link flags are supplied
# on the compile command; see the build recipe above and c-smoke.sh.

# Pull declarations straight from the header via importc, so struct layout and
# signatures are the C compiler's, not hand-transcribed. cbindgen emits the
# tagged unions as `{ tag; union { HEADING; PARAGRAPH; ... }; }`; because these
# are importc + header types, Nim never computes the layout itself — it defers
# to the C header — so we only declare the union members we actually read, each
# with its C name, and access `blk.heading` compiles to `blk.HEADING`, which C
# resolves through the anonymous union.
{.push header: "marmot.h".}

type
  MarmotClient {.importc: "MarmotClient", incompleteStruct.} = object
  MarmotStringList {.importc: "MarmotStringList", incompleteStruct.} = object

  MarmotStatus {.importc: "MarmotStatus".} = distinct cint
  MarmotMarkdownBlockTag {.importc: "MarmotMarkdownBlock_Tag".} = distinct cint
  MarmotMarkdownInlineTag {.importc: "MarmotMarkdownInline_Tag".} = distinct cint

  # --- inline nodes (leaf bodies we reconstruct heading text from) -----
  MarmotMarkdownInlineTextBody {.importc: "MarmotMarkdownInline_Text_Body".} = object
    content {.importc: "content".}: cstring
  MarmotMarkdownInlineCodeBody {.importc: "MarmotMarkdownInline_Code_Body".} = object
    content {.importc: "content".}: cstring
  MarmotMarkdownInline {.importc: "MarmotMarkdownInline".} = object
    tag {.importc: "tag".}: MarmotMarkdownInlineTag
    text {.importc: "TEXT".}: MarmotMarkdownInlineTextBody
    code {.importc: "CODE".}: MarmotMarkdownInlineCodeBody

  # --- block bodies (only the fields this walk touches) ----------------
  MarmotMarkdownHeadingBody {.importc: "MarmotMarkdownBlock_Heading_Body".} = object
    level {.importc: "level".}: uint8
    inlines {.importc: "inlines".}: ptr UncheckedArray[MarmotMarkdownInline]
    inlines_len {.importc: "inlines_len".}: csize_t
  MarmotMarkdownParagraphBody {.importc: "MarmotMarkdownBlock_Paragraph_Body".} = object
    inlines {.importc: "inlines".}: ptr UncheckedArray[MarmotMarkdownInline]
    inlines_len {.importc: "inlines_len".}: csize_t
  MarmotMarkdownCodeBlockBody {.importc: "MarmotMarkdownBlock_CodeBlock_Body".} = object
    info {.importc: "info".}: cstring
    content {.importc: "content".}: cstring
  MarmotMarkdownListBlockBody {.importc: "MarmotMarkdownBlock_ListBlock_Body".} = object
    items_len {.importc: "items_len".}: csize_t
  MarmotMarkdownBlock {.importc: "MarmotMarkdownBlock".} = object
    tag {.importc: "tag".}: MarmotMarkdownBlockTag
    heading {.importc: "HEADING".}: MarmotMarkdownHeadingBody
    paragraph {.importc: "PARAGRAPH".}: MarmotMarkdownParagraphBody
    codeBlock {.importc: "CODE_BLOCK".}: MarmotMarkdownCodeBlockBody
    listBlock {.importc: "LIST_BLOCK".}: MarmotMarkdownListBlockBody

  MarmotMarkdownDocument {.importc: "MarmotMarkdownDocument".} = object
    blocks: ptr UncheckedArray[MarmotMarkdownBlock]
    blocks_len: csize_t
    truncated: bool

  MarmotAccountSummary {.importc: "MarmotAccountSummary".} = object
    label {.importc: "label".}: cstring
    account_id_hex {.importc: "account_id_hex".}: cstring
    local_signing {.importc: "local_signing".}: bool
    signed_out {.importc: "signed_out".}: bool
    running {.importc: "running".}: bool

  MarmotAccountSummaryList {.importc: "MarmotAccountSummaryList".} = object
    items: ptr MarmotAccountSummary
    len: csize_t

var
  MARMOT_STATUS_OK {.importc, nodecl.}: MarmotStatus
  MARMOT_STATUS_NULL_POINTER {.importc, nodecl.}: MarmotStatus
  MARMOT_STATUS_UNKNOWN_ACCOUNT {.importc, nodecl.}: MarmotStatus
  MARMOT_MARKDOWN_BLOCK_HEADING {.importc, nodecl.}: MarmotMarkdownBlockTag
  MARMOT_MARKDOWN_BLOCK_PARAGRAPH {.importc, nodecl.}: MarmotMarkdownBlockTag
  MARMOT_MARKDOWN_BLOCK_CODE_BLOCK {.importc, nodecl.}: MarmotMarkdownBlockTag
  MARMOT_MARKDOWN_BLOCK_LIST_BLOCK {.importc, nodecl.}: MarmotMarkdownBlockTag
  MARMOT_MARKDOWN_INLINE_TEXT {.importc, nodecl.}: MarmotMarkdownInlineTag
  MARMOT_MARKDOWN_INLINE_CODE {.importc, nodecl.}: MarmotMarkdownInlineTag

proc marmot_client_new(root_path: cstring, relay_urls: ptr cstring,
                       relay_urls_len: csize_t, out_client: ptr ptr MarmotClient): MarmotStatus {.importc.}
proc marmot_client_start(client: ptr MarmotClient): MarmotStatus {.importc.}
proc marmot_client_shutdown(client: ptr MarmotClient): MarmotStatus {.importc.}
proc marmot_client_is_stopping(client: ptr MarmotClient, out_stopping: ptr bool): MarmotStatus {.importc.}
proc marmot_client_free(client: ptr MarmotClient) {.importc.}
proc marmot_last_error_message(): cstring {.importc.}
proc marmot_string_free(s: cstring) {.importc.}
proc marmot_parse_markdown(client: ptr MarmotClient, text: cstring,
                           out_document: ptr ptr MarmotMarkdownDocument): MarmotStatus {.importc.}
proc marmot_markdown_document_free(document: ptr MarmotMarkdownDocument) {.importc.}
proc marmot_list_accounts(client: ptr MarmotClient,
                          out_list: ptr ptr MarmotAccountSummaryList): MarmotStatus {.importc.}
proc marmot_account_summary_list_free(list: ptr MarmotAccountSummaryList) {.importc.}
proc marmot_account_summary_free(summary: ptr MarmotAccountSummary) {.importc.}
proc marmot_account_nip65_relays(client: ptr MarmotClient, account_ref: cstring,
                                 out_list: ptr ptr MarmotStringList): MarmotStatus {.importc.}
proc marmot_string_list_free(list: ptr MarmotStringList) {.importc.}
proc marmot_npub(client: ptr MarmotClient, account_id_hex: cstring,
                 out_npub: ptr cstring): MarmotStatus {.importc.}
proc marmot_reveal_nsec(client: ptr MarmotClient, account_ref: cstring,
                        out_nsec: ptr cstring): MarmotStatus {.importc.}
proc marmot_create_identity(client: ptr MarmotClient,
                            default_relays: ptr cstring, default_relays_len: csize_t,
                            bootstrap_relays: ptr cstring, bootstrap_relays_len: csize_t,
                            out_summary: ptr ptr MarmotAccountSummary): MarmotStatus {.importc.}

{.pop.}

proc `==`(a, b: MarmotStatus): bool {.borrow.}
proc `==`(a, b: MarmotMarkdownBlockTag): bool {.borrow.}
proc `==`(a, b: MarmotMarkdownInlineTag): bool {.borrow.}

# --------------------------------------------------------------------------
# Idiomatic wrapper: a `Marmot` handle that raises `MarmotError` on any
# non-OK status and frees the client on destruction. The raw out-pointer
# dance stays hidden inside these procs.
# --------------------------------------------------------------------------

type
  MarmotError = object of CatchableError
    status: MarmotStatus

  Marmot = object
    client: ptr MarmotClient

  # RAII owner for a parsed document, freed as one root by `=destroy`.
  Markdown = object
    doc: ptr MarmotMarkdownDocument

proc `=copy`(dst: var Marmot, src: Marmot) {.error.}
proc `=copy`(dst: var Markdown, src: Markdown) {.error.}

proc `=destroy`(m: Marmot) =
  if m.client != nil:
    marmot_client_free(m.client)

proc `=destroy`(m: Markdown) =
  if m.doc != nil:
    marmot_markdown_document_free(m.doc)

# Take and free the thread-local detail for the most recent failure.
proc lastError(): string =
  let msg = marmot_last_error_message()
  result = if msg != nil: $msg else: "(no detail)"
  marmot_string_free(msg)

# Raise `MarmotError` (carrying the status code + last-error detail) unless
# `status` is OK. The single choke point every wrapper proc funnels through.
proc check(status: MarmotStatus, context: string) =
  if status != MARMOT_STATUS_OK:
    var e = newException(MarmotError, context & ": " & lastError())
    e.status = status
    raise e

proc open(root: string, relays: openArray[string]): Marmot =
  # `allocCStringArray` copies each URL into C-owned memory that outlives the
  # call. Borrowing `r.cstring` from the loop variable would dangle once the
  # temporary Nim string is freed under ARC/ORC.
  let arr = allocCStringArray(relays)
  defer: deallocCStringArray(arr)
  var client: ptr MarmotClient = nil
  check(marmot_client_new(root.cstring, cast[ptr cstring](arr), csize_t(relays.len), addr client),
        "client_new")
  result.client = client

proc isStopping(m: Marmot): bool =
  var stopping = true
  check(marmot_client_is_stopping(m.client, addr stopping), "is_stopping")
  stopping

# Best-effort start: OK online, a typed error offline. Returns the message on
# the offline path so the caller can report the outcome without failing.
proc tryStart(m: Marmot): Option[string] =
  let st = marmot_client_start(m.client)
  if st == MARMOT_STATUS_OK: none(string) else: some(lastError())

proc parseMarkdown(m: Marmot, text: string): Markdown =
  var doc: ptr MarmotMarkdownDocument = nil
  check(marmot_parse_markdown(m.client, text.cstring, addr doc), "parse_markdown")
  result.doc = doc

proc truncated(md: Markdown): bool = md.doc.truncated
proc blockCount(md: Markdown): int = md.doc.blocks_len.int

# Reconstruct the plain text of an inline run by concatenating its Text and
# Code spans — a small walk of the inline tagged union.
proc inlineText(inlines: ptr UncheckedArray[MarmotMarkdownInline], n: csize_t): string =
  for i in 0 ..< n.int:
    let inl = inlines[i]
    if inl.tag == MARMOT_MARKDOWN_INLINE_TEXT:
      result.add $inl.text.content
    elif inl.tag == MARMOT_MARKDOWN_INLINE_CODE:
      result.add "`" & $inl.code.content & "`"

# Walk the top-level blocks, classifying each by tag and reaching into the
# union body; reconstruct heading text from its inlines. Returns the heading
# count seen.
proc walk(md: Markdown): int =
  let doc = md.doc
  for i in 0 ..< doc.blocks_len.int:
    let blk = doc.blocks[i]
    if blk.tag == MARMOT_MARKDOWN_BLOCK_HEADING:
      inc result
      let h = blk.heading
      echo "smoke(nim):   block ", i, ": heading (h", h.level, ") \"",
           inlineText(h.inlines, h.inlines_len), "\""
    elif blk.tag == MARMOT_MARKDOWN_BLOCK_PARAGRAPH:
      let p = blk.paragraph
      echo "smoke(nim):   block ", i, ": paragraph \"",
           inlineText(p.inlines, p.inlines_len), "\""
    elif blk.tag == MARMOT_MARKDOWN_BLOCK_CODE_BLOCK:
      let c = blk.codeBlock
      echo "smoke(nim):   block ", i, ": code block (lang=",
           (if c.info != nil: $c.info else: ""), ")"
    elif blk.tag == MARMOT_MARKDOWN_BLOCK_LIST_BLOCK:
      echo "smoke(nim):   block ", i, ": list with ", blk.listBlock.items_len, " items"
    else:
      echo "smoke(nim):   block ", i, ": other"

proc accountCount(m: Marmot): int =
  var accounts: ptr MarmotAccountSummaryList = nil
  check(marmot_list_accounts(m.client, addr accounts), "list_accounts")
  result = accounts.len.int
  marmot_account_summary_list_free(accounts)

# Directory lookup: an absent id resolves to OK with a NULL string.
proc npub(m: Marmot, accountIdHex: string): Option[string] =
  var outNpub: cstring = nil
  check(marmot_npub(m.client, accountIdHex.cstring, addr outNpub), "npub")
  if outNpub == nil:
    result = none(string)
  else:
    result = some($outNpub)
    marmot_string_free(outNpub)

proc nip65Relays(m: Marmot, accountRef: string): seq[string] =
  var lst: ptr MarmotStringList = nil
  check(marmot_account_nip65_relays(m.client, accountRef.cstring, addr lst), "nip65_relays")
  # Reached only on success; the smoke run always exercises the error path.
  marmot_string_list_free(lst)

proc revealNsec(m: Marmot, accountRef: string): string =
  var outNsec: cstring = nil
  check(marmot_reveal_nsec(m.client, accountRef.cstring, addr outNsec), "reveal_nsec")
  result = if outNsec != nil: $outNsec else: ""
  marmot_string_free(outNsec)

# Best-effort identity publish: returns the account id hex online, or raises
# the typed error offline/rejected.
proc createIdentity(m: Marmot, relays: openArray[string]): string =
  # Owned C-string copies that outlive the call (see `open`).
  let arr = allocCStringArray(relays)
  defer: deallocCStringArray(arr)
  let relayPtr = cast[ptr cstring](arr)
  var summary: ptr MarmotAccountSummary = nil
  check(marmot_create_identity(m.client, relayPtr, csize_t(relays.len),
                               relayPtr, csize_t(relays.len), addr summary),
        "create_identity")
  result = if summary.account_id_hex != nil: $summary.account_id_hex else: ""
  marmot_account_summary_free(summary)

proc shutdown(m: Marmot) =
  check(marmot_client_shutdown(m.client), "shutdown")

# --------------------------------------------------------------------------

proc expect(cond: bool, what: string) =
  if not cond:
    stdout.writeLine("smoke(nim): FAILED: " & what)
    quit(1)
  stdout.writeLine("smoke(nim): ok: " & what)

proc main() =
  if paramCount() != 1:
    stderr.writeLine("usage: smoke_nim <fresh-home-dir>")
    quit(2)
  let home = paramStr(1)

  # --- argument validation + NULL-free discipline (no client) --------
  block:
    var client: ptr MarmotClient = nil
    let st = marmot_client_new(nil, nil, 0, addr client)
    expect(st == MARMOT_STATUS_NULL_POINTER, "NULL root_path rejected")

  # NULL is a no-op for every free function.
  marmot_client_free(nil)
  marmot_string_free(nil)
  marmot_account_summary_list_free(nil)
  marmot_markdown_document_free(nil)
  stdout.writeLine("smoke(nim): ok: NULL frees are no-ops")

  # --- construct + lifecycle -----------------------------------------
  var marmot: Marmot
  try:
    marmot = open(home, ["wss://relay.example.org"])
  except MarmotError as e:
    # Headless environments may lack a platform keychain; a documented
    # limitation, not an ABI defect.
    stdout.writeLine("smoke(nim): SKIP: " & e.msg)
    quit(0)
  expect(marmot.client != nil, "client constructed")

  expect(not marmot.isStopping(), "client not stopping")

  # start() may fail offline (dial-safety rejects unreachable relays); that
  # still exercises the start + error path. Either outcome is fine.
  let startErr = marmot.tryStart()
  if startErr.isNone:
    stdout.writeLine("smoke(nim): ok: client started")
  else:
    stdout.writeLine("smoke(nim): ok: client start returned offline error: " & startErr.get)

  # --- markdown: parse + DEEP walk of the recursive DTO tree ---------
  const md =
    "# Marmot\n\n" &
    "A **bold** claim with `code` and a [link](https://example.org).\n\n" &
    "- [x] dig burrow\n" &
    "- [ ] store acorns\n\n" &
    "```rust\nfn main() {}\n```\n"
  let doc = marmot.parseMarkdown(md)
  expect(not doc.truncated, "markdown not truncated")
  expect(doc.blockCount >= 4, "markdown has heading + paragraph + list + code")
  expect(doc.walk() == 1, "walked tree found exactly one heading")

  # --- offline reads -------------------------------------------------
  expect(marmot.accountCount() == 0, "fresh home has no accounts")

  # Directory lookup: the call resolves with OK (a well-formed id encodes to
  # an npub; a malformed one yields absent). Either way it must not raise.
  let unknownId = "0000000000000000000000000000000000000000000000000000000000000000"
  discard marmot.npub(unknownId)
  expect(true, "npub lookup call succeeds")

  # --- error taxonomy (hard asserts on typed status) -----------------
  try:
    discard marmot.nip65Relays("no-such-account")
    expect(false, "nip65 on unknown account should raise")
  except MarmotError as e:
    expect(e.status == MARMOT_STATUS_UNKNOWN_ACCOUNT,
           "unknown account -> MARMOT_STATUS_UNKNOWN_ACCOUNT")

  try:
    discard marmot.revealNsec("no-such-account")
    expect(false, "reveal_nsec on unknown account should raise")
  except MarmotError as e:
    expect(e.status == MARMOT_STATUS_UNKNOWN_ACCOUNT,
           "reveal_nsec on unknown account -> UNKNOWN_ACCOUNT")

  # --- best-effort identity (needs a relay) --------------------------
  try:
    let id = marmot.createIdentity(["wss://relay.example.org"])
    stdout.writeLine("smoke(nim): ok: identity created: " & id)
  except MarmotError as e:
    stdout.writeLine("smoke(nim): ok: identity create offline: " & e.msg)

  # --- shutdown ------------------------------------------------------
  marmot.shutdown()
  expect(marmot.isStopping(), "client reports stopping")

  # `marmot` (and its client) is freed by `=destroy` at scope exit.
  stdout.writeLine("smoke(nim): all checks passed")

main()
