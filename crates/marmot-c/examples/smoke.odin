// Worked example / smoke test for the marmot-c ABI, in Odin.
//
// Odin has no C-header import, so the subset of the ABI used here is
// hand-declared in a `foreign` block. That doubles as a check that a non-C,
// non-cbindgen consumer can reproduce the struct layout and calling
// convention. It drives a realistic slice of the runtime and mirrors the
// FLOW of examples/smoke.c: argument validation, client lifecycle, the
// error + last-error paths, Markdown parsing, offline directory/list reads,
// the typed error taxonomy, and best-effort identity creation.
//
// Idiomatically this wraps the raw calls in a `Marmot` handle, threads a
// `Marmot_Error` (status + owned detail) through Odin's `or_return` and
// multiple-return `(value, err)` idiom, and cleans up with
// `defer marmot_close(&m)`. No out-parameter plumbing leaks into main.
//
// The Markdown DTO is only touched at DOCUMENT level here: the recursive
// tagged-union walk (heading/paragraph/list/code blocks and their inline
// runs) is a transcription hazard to hand-declare, so examples/smoke.c is
// the reference for that deep walk.
//
// Build & run (see c-smoke.sh for the canonical invocation). Links the
// SHARED library (so the run needs it on the loader path), which nicely
// complements the C/Zig tests that link the static archive:
//   odin build examples/smoke.odin -file -out:smoke_odin \
//       -extra-linker-flags:"-Ltarget/debug -lmarmot_c -lm -lpthread -ldl"
//   LD_LIBRARY_PATH=target/debug ./smoke_odin <fresh-empty-home-dir>

package smoke

import "core:fmt"
import "core:os"
import "core:strings"

// Opaque handles: only ever held by pointer.
Marmot_Client :: struct {}
Marmot_Markdown_Block :: struct {}
Marmot_String_List :: struct {}

// Subset of MarmotStatus actually asserted here (values are stable ABI).
Marmot_Status :: enum i32 {
	Ok              = 0,
	Null_Pointer    = 1,
	Unknown_Account = 11,
}

// Mirror of MarmotMarkdownDocument (document level only — see file header).
Marmot_Markdown_Document :: struct {
	blocks:     ^Marmot_Markdown_Block,
	blocks_len: uint,
	truncated:  bool,
}

// Mirror of MarmotAccountSummary.
Marmot_Account_Summary :: struct {
	label:          cstring,
	account_id_hex: cstring,
	local_signing:  bool,
	signed_out:     bool,
	running:        bool,
}

// Mirror of MarmotAccountSummaryList.
Marmot_Account_Summary_List :: struct {
	items: ^Marmot_Account_Summary,
	len:   uint,
}

// Linked as a shared library: build with
//   -extra-linker-flags:"-L<dir-containing-libmarmot_c.so> -lmarmot_c -lm -lpthread -ldl"
foreign import marmot "system:marmot_c"

@(default_calling_convention = "c")
foreign marmot {
	marmot_client_new :: proc(root_path: cstring, relay_urls: [^]cstring, relay_urls_len: uint, out_client: ^^Marmot_Client) -> Marmot_Status ---
	marmot_client_start :: proc(client: ^Marmot_Client) -> Marmot_Status ---
	marmot_client_shutdown :: proc(client: ^Marmot_Client) -> Marmot_Status ---
	marmot_client_is_stopping :: proc(client: ^Marmot_Client, out_stopping: ^bool) -> Marmot_Status ---
	marmot_client_free :: proc(client: ^Marmot_Client) ---
	marmot_last_error_message :: proc() -> cstring ---
	marmot_string_free :: proc(s: cstring) ---
	marmot_parse_markdown :: proc(client: ^Marmot_Client, text: cstring, out_document: ^^Marmot_Markdown_Document) -> Marmot_Status ---
	marmot_markdown_document_free :: proc(document: ^Marmot_Markdown_Document) ---
	marmot_list_accounts :: proc(client: ^Marmot_Client, out_list: ^^Marmot_Account_Summary_List) -> Marmot_Status ---
	marmot_account_summary_list_free :: proc(list: ^Marmot_Account_Summary_List) ---
	marmot_account_summary_free :: proc(summary: ^Marmot_Account_Summary) ---
	marmot_account_nip65_relays :: proc(client: ^Marmot_Client, account_ref: cstring, out_list: ^^Marmot_String_List) -> Marmot_Status ---
	marmot_npub :: proc(client: ^Marmot_Client, account_id_hex: cstring, out_npub: ^cstring) -> Marmot_Status ---
	marmot_reveal_nsec :: proc(client: ^Marmot_Client, account_ref: cstring, out_nsec: ^cstring) -> Marmot_Status ---
	marmot_create_identity :: proc(client: ^Marmot_Client, default_relays: [^]cstring, default_relays_len: uint, bootstrap_relays: [^]cstring, bootstrap_relays_len: uint, out_summary: ^^Marmot_Account_Summary) -> Marmot_Status ---
}

// ---- idiomatic wrapper -----------------------------------------------------

// A non-Ok status plus the thread-local detail string, cloned into Odin
// storage. Modelled as a union so `nil` is the "no error" value, which is
// what lets it flow through Odin's `or_return`. Free with `free_err`.
Marmot_Fault :: struct {
	status: Marmot_Status,
	detail: string,
}
Marmot_Error :: union {
	Marmot_Fault,
}

// The check helper: turn a raw status into a Marmot_Error, reading
// marmot_last_error_message for the detail on failure (nil on success).
check :: proc(st: Marmot_Status) -> Marmot_Error {
	if st == .Ok do return nil
	detail: string
	if msg := marmot_last_error_message(); msg != nil {
		detail = strings.clone(string(msg))
		marmot_string_free(msg)
	}
	return Marmot_Fault{status = st, detail = detail}
}

// Accessors that treat nil as success.
status_of :: proc(err: Marmot_Error) -> Marmot_Status {
	if f, ok := err.(Marmot_Fault); ok do return f.status
	return .Ok
}
detail_of :: proc(err: Marmot_Error) -> string {
	if f, ok := err.(Marmot_Fault); ok do return f.detail
	return ""
}
free_err :: proc(err: Marmot_Error) {
	if f, ok := err.(Marmot_Fault); ok do delete(f.detail)
}

// Owned client handle. Held by value; the pointer inside is the ABI object.
Marmot :: struct {
	client: ^Marmot_Client,
}

marmot_open :: proc(home: string, relays: []cstring) -> (m: Marmot, err: Marmot_Error) {
	croot := strings.clone_to_cstring(home)
	defer delete(croot)
	check(marmot_client_new(croot, raw_data(relays), len(relays), &m.client)) or_return
	return
}

// RAII-style cleanup: shutdown (idempotent) then deep-free the handle.
// Safe on a zero/failed handle, so it works as a `defer` on every path.
marmot_close :: proc(m: ^Marmot) {
	if m.client == nil do return
	marmot_client_shutdown(m.client)
	marmot_client_free(m.client)
	m.client = nil
}

is_stopping :: proc(m: Marmot) -> (stopping: bool, err: Marmot_Error) {
	err = check(marmot_client_is_stopping(m.client, &stopping))
	return
}

// Directory lookup: an absent id resolves to OK with a NULL string, which
// this returns as "".
npub_of :: proc(m: Marmot, account_id_hex: string) -> (npub: string, err: Marmot_Error) {
	cid := strings.clone_to_cstring(account_id_hex)
	defer delete(cid)
	out: cstring
	check(marmot_npub(m.client, cid, &out)) or_return
	if out != nil {
		npub = strings.clone(string(out))
		marmot_string_free(out)
	}
	return
}

nip65_relays :: proc(m: Marmot, account_ref: string) -> Marmot_Error {
	cref := strings.clone_to_cstring(account_ref)
	defer delete(cref)
	out: ^Marmot_String_List
	return check(marmot_account_nip65_relays(m.client, cref, &out))
}

reveal_nsec :: proc(m: Marmot, account_ref: string) -> Marmot_Error {
	cref := strings.clone_to_cstring(account_ref)
	defer delete(cref)
	out: cstring
	err := check(marmot_reveal_nsec(m.client, account_ref = cref, out_nsec = &out))
	if out != nil do marmot_string_free(out)
	return err
}

// ---- assertions ------------------------------------------------------------

fail :: proc(what: string) -> ! {
	fmt.eprintfln("smoke(odin): FAILED: %s", what)
	os.exit(1)
}

expect :: proc(condition: bool, what: string) {
	if !condition do fail(what)
	fmt.printfln("smoke(odin): ok: %s", what)
}

main :: proc() {
	if len(os.args) != 2 {
		fmt.eprintln("usage: smoke_odin <fresh-home-dir>")
		os.exit(2)
	}
	home := os.args[1]

	// --- argument validation paths (no client needed) ------------------
	client: ^Marmot_Client
	st := marmot_client_new(nil, nil, 0, &client)
	expect(st == .Null_Pointer, "NULL root_path rejected")

	// NULL is a no-op for every free function.
	marmot_client_free(nil)
	marmot_string_free(nil)
	marmot_account_summary_list_free(nil)
	marmot_account_summary_free(nil)
	marmot_markdown_document_free(nil)
	fmt.println("smoke(odin): ok: NULL frees are no-ops")

	// --- construct + lifecycle -----------------------------------------
	relays := [?]cstring{"wss://relay.example.org"}
	m, err := marmot_open(home, relays[:])
	if err != nil {
		// No platform keychain (headless): a documented limitation.
		fmt.printfln("smoke(odin): SKIP: no client (status %d): %s", i32(status_of(err)), detail_of(err))
		free_err(err)
		os.exit(0)
	}
	defer marmot_close(&m)
	fmt.println("smoke(odin): ok: client constructed")

	stopping, serr0 := is_stopping(m)
	expect(serr0 == nil && !stopping, "client not stopping")

	// start() may fail offline (dial-safety); either outcome is fine.
	if serr := check(marmot_client_start(m.client)); serr == nil {
		fmt.println("smoke(odin): ok: client started")
	} else {
		fmt.printfln("smoke(odin): ok: client start offline (status %d): %s", i32(status_of(serr)), detail_of(serr))
		free_err(serr)
	}

	// --- markdown: parse at document level (see file header) -----------
	doc: ^Marmot_Markdown_Document
	md := "# Marmot\n\nA **bold** claim with `code` and a [link](https://example.org).\n\n- [x] dig burrow\n- [ ] store acorns\n\n```rust\nfn main() {}\n```\n"
	cmd := strings.clone_to_cstring(md)
	defer delete(cmd)
	perr := check(marmot_parse_markdown(m.client, cmd, &doc))
	expect(perr == nil && doc != nil, "markdown parsed")
	expect(!doc.truncated, "markdown not truncated")
	expect(doc.blocks_len >= 4, "markdown has heading + paragraph + list + code")
	marmot_markdown_document_free(doc)

	// --- offline reads -------------------------------------------------
	accounts: ^Marmot_Account_Summary_List
	expect(check(marmot_list_accounts(m.client, &accounts)) == nil && accounts != nil, "list_accounts")
	expect(accounts.len == 0, "fresh home has no accounts")
	marmot_account_summary_list_free(accounts)

	// Directory lookup for an unknown id: the call resolves OK; an absent
	// id comes back as a NULL string (here "").
	zero_id := "0000000000000000000000000000000000000000000000000000000000000000"
	npub, nerr := npub_of(m, zero_id)
	expect(nerr == nil, "npub lookup call succeeds")
	delete(npub)

	// --- error taxonomy (hard asserts) ---------------------------------
	nerr65 := nip65_relays(m, "no-such-account")
	expect(status_of(nerr65) == .Unknown_Account, "nip65 on unknown account -> UNKNOWN_ACCOUNT")
	free_err(nerr65)
	rerr := reveal_nsec(m, "no-such-account")
	expect(status_of(rerr) == .Unknown_Account, "reveal_nsec on unknown account -> UNKNOWN_ACCOUNT")
	free_err(rerr)

	// --- best-effort identity (needs a relay) --------------------------
	summary: ^Marmot_Account_Summary
	ierr := check(marmot_create_identity(m.client, raw_data(relays[:]), len(relays), raw_data(relays[:]), len(relays), &summary))
	if ierr == nil && summary != nil {
		fmt.printfln("smoke(odin): ok: identity created: %s", summary.account_id_hex)
		marmot_account_summary_free(summary)
	} else {
		fmt.printfln("smoke(odin): ok: identity create offline (status %d): %s", i32(status_of(ierr)), detail_of(ierr))
		free_err(ierr)
	}

	// --- shutdown ------------------------------------------------------
	expect(check(marmot_client_shutdown(m.client)) == nil, "client shutdown")
	stopping2, serr1 := is_stopping(m)
	expect(serr1 == nil && stopping2, "client reports stopping")

	fmt.println("smoke(odin): all checks passed")
}
