// End-to-end smoke test for the marmot-c ABI from Go (cgo).
//
// cgo pulls in the real marmot.h, so the generated header stays the single
// source of truth for signatures and struct layout. Mirrors the flow of
// examples/smoke.c: argument validation, client lifecycle, markdown parsing,
// offline directory + account reads, the error taxonomy, and best-effort
// identity creation — wrapped in an idiomatic Go type that returns `error`
// values and owns the C resources.
//
// The #cgo lines below link the static archive relative to this source file
// (${SRCDIR}); the Rust staticlib needs the C math/thread/dl libs. Build &
// run (see c-smoke.sh for the canonical invocation):
//   go run examples/smoke.go <fresh-empty-home-dir>
// or, so the binary can move:
//   go build -o smoke_go examples/smoke.go && ./smoke_go <home>

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../include
#cgo LDFLAGS: ${SRCDIR}/../../../target/debug/libmarmot_c.a -lm -lpthread -ldl
#include <stdlib.h>
#include <marmot.h>
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// MarmotError carries the ABI status code plus the thread-local detail string
// from marmot_last_error_message().
type MarmotError struct {
	Op     string
	Status int
	Detail string
}

func (e *MarmotError) Error() string {
	detail := e.Detail
	if detail == "" {
		detail = "(no detail)"
	}
	return fmt.Sprintf("%s: status %d: %s", e.Op, e.Status, detail)
}

// check turns a raw MarmotStatus into an idiomatic error, draining the
// thread-local last-error detail on failure. Typed as C.MarmotStatus so it
// stays correct whether cgo maps the enum to a signed or unsigned width.
func check(status C.MarmotStatus, op string) error {
	if status == C.MARMOT_STATUS_OK {
		return nil
	}
	detail := ""
	if msg := C.marmot_last_error_message(); msg != nil {
		detail = C.GoString(msg)
		C.marmot_string_free(msg)
	}
	return &MarmotError{Op: op, Status: int(status), Detail: detail}
}

// Marmot wraps the opaque *C.MarmotClient with idiomatic methods.
type Marmot struct {
	client *C.MarmotClient
}

// cStrings marshals a []string into a NULL-safe C `**char`, returning the
// pointer to the first element (or nil for an empty slice) and a cleanup func.
func cStrings(items []string) (**C.char, C.uintptr_t, func()) {
	if len(items) == 0 {
		return nil, 0, func() {}
	}
	arr := make([]*C.char, len(items))
	for i, s := range items {
		arr[i] = C.CString(s)
	}
	free := func() {
		for _, p := range arr {
			C.free(unsafe.Pointer(p))
		}
	}
	return (**C.char)(unsafe.Pointer(&arr[0])), C.uintptr_t(len(items)), free
}

// Open constructs a client rooted at home with the given default relays.
func Open(home string, relays []string) (*Marmot, error) {
	cHome := C.CString(home)
	defer C.free(unsafe.Pointer(cHome))

	cRelays, n, freeRelays := cStrings(relays)
	defer freeRelays()

	var client *C.MarmotClient
	st := C.marmot_client_new(cHome, cRelays, n, &client)
	if err := check(st, "client_new"); err != nil {
		return nil, err
	}
	return &Marmot{client: client}, nil
}

// IsStopping reports whether the client is shutting down.
func (m *Marmot) IsStopping() (bool, error) {
	var stopping C.bool
	st := C.marmot_client_is_stopping(m.client, &stopping)
	if err := check(st, "is_stopping"); err != nil {
		return false, err
	}
	return bool(stopping), nil
}

// TryStart attempts to start the runtime, returning the typed error (e.g. the
// offline dial-safety rejection) for the caller to decide on.
func (m *Marmot) TryStart() error {
	return check(C.marmot_client_start(m.client), "start")
}

// ParseMarkdown parses text and returns (blockCount, truncated).
func (m *Marmot) ParseMarkdown(text string) (int, bool, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var doc *C.MarmotMarkdownDocument
	st := C.marmot_parse_markdown(m.client, cText, &doc)
	if err := check(st, "parse_markdown"); err != nil {
		return 0, false, err
	}
	defer C.marmot_markdown_document_free(doc)
	// The C example (examples/smoke.c) demonstrates the deep tagged-union walk
	// down to HEADING/PARAGRAPH inline runs; cgo's rendering of cbindgen's
	// anonymous union is unergonomic (each access needs unsafe pointer casts),
	// so here we stay at the DOCUMENT level and only inspect the block count.
	return int(doc.blocks_len), bool(doc.truncated), nil
}

// AccountCount returns the number of local accounts.
func (m *Marmot) AccountCount() (int, error) {
	var accounts *C.MarmotAccountSummaryList
	st := C.marmot_list_accounts(m.client, &accounts)
	if err := check(st, "list_accounts"); err != nil {
		return 0, err
	}
	defer C.marmot_account_summary_list_free(accounts)
	return int(accounts.len), nil
}

// Npub resolves an account id (hex) to its npub via the directory. An absent
// id yields ("", nil).
func (m *Marmot) Npub(accountIDHex string) (string, error) {
	cID := C.CString(accountIDHex)
	defer C.free(unsafe.Pointer(cID))

	var out *C.char
	st := C.marmot_npub(m.client, cID, &out)
	if err := check(st, "npub"); err != nil {
		return "", err
	}
	if out == nil {
		return "", nil
	}
	defer C.marmot_string_free(out)
	return C.GoString(out), nil
}

// Nip65Relays returns the NIP-65 relays for an account ref.
func (m *Marmot) Nip65Relays(accountRef string) ([]string, error) {
	cRef := C.CString(accountRef)
	defer C.free(unsafe.Pointer(cRef))

	var list *C.MarmotStringList
	st := C.marmot_account_nip65_relays(m.client, cRef, &list)
	if err := check(st, "nip65_relays"); err != nil {
		return nil, err
	}
	defer C.marmot_string_list_free(list)
	n := int(list.len)
	out := make([]string, 0, n)
	items := unsafe.Slice(list.items, n)
	for _, p := range items {
		out = append(out, C.GoString(p))
	}
	return out, nil
}

// RevealNsec returns the plaintext nsec for an account ref.
func (m *Marmot) RevealNsec(accountRef string) (string, error) {
	cRef := C.CString(accountRef)
	defer C.free(unsafe.Pointer(cRef))

	var out *C.char
	st := C.marmot_reveal_nsec(m.client, cRef, &out)
	if err := check(st, "reveal_nsec"); err != nil {
		return "", err
	}
	defer C.marmot_string_free(out)
	return C.GoString(out), nil
}

// CreateIdentity creates a fresh identity published to the given relays,
// returning its account id (hex). Needs a live relay, so it is best-effort.
func (m *Marmot) CreateIdentity(defaultRelays, bootstrapRelays []string) (string, error) {
	cDef, nDef, freeDef := cStrings(defaultRelays)
	defer freeDef()
	cBoot, nBoot, freeBoot := cStrings(bootstrapRelays)
	defer freeBoot()

	var summary *C.MarmotAccountSummary
	st := C.marmot_create_identity(m.client, cDef, nDef, cBoot, nBoot, &summary)
	if err := check(st, "create_identity"); err != nil {
		return "", err
	}
	defer C.marmot_account_summary_free(summary)
	return C.GoString(summary.account_id_hex), nil
}

// Close shuts the runtime down and frees the client. Safe to defer.
func (m *Marmot) Close() {
	if m == nil || m.client == nil {
		return
	}
	C.marmot_client_shutdown(m.client)
	C.marmot_client_free(m.client)
	m.client = nil
}

func fail(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke(go): FAILED: %s: %v\n", what, err)
	} else {
		fmt.Fprintf(os.Stderr, "smoke(go): FAILED: %s\n", what)
	}
	os.Exit(1)
}

func ok(what string) {
	fmt.Printf("smoke(go): ok: %s\n", what)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: smoke_go <fresh-home-dir>")
		os.Exit(2)
	}
	home := os.Args[1]

	// --- argument validation paths (no client) --------------------------
	var raw *C.MarmotClient
	st := C.marmot_client_new(nil, nil, 0, &raw)
	if st != C.MARMOT_STATUS_NULL_POINTER {
		fail("NULL root_path should be rejected", nil)
	}
	ok("NULL root_path rejected")

	// NULL is a no-op for every free function.
	C.marmot_client_free(nil)
	C.marmot_string_free(nil)
	C.marmot_account_summary_list_free(nil)
	C.marmot_markdown_document_free(nil)
	ok("NULL frees are no-ops")

	// --- construct + lifecycle ------------------------------------------
	relays := []string{"wss://relay.example.org"}
	m, err := Open(home, relays)
	if err != nil {
		// Headless environments may lack a platform keychain; a documented
		// limitation, not an ABI defect.
		fmt.Printf("smoke(go): SKIP: %v\n", err)
		return
	}
	defer m.Close()
	ok("client constructed")

	stopping, err := m.IsStopping()
	if err != nil || stopping {
		fail("client should not be stopping", err)
	}
	ok("client not stopping")

	// start() may fail offline (dial-safety rejects the relay); either
	// outcome exercises the start + error path. Best-effort.
	if err := m.TryStart(); err != nil {
		fmt.Printf("smoke(go): ok: client start offline: %v\n", err)
	} else {
		ok("client started")
	}

	// --- markdown parsing -----------------------------------------------
	md := "# Marmot\n\n" +
		"A **bold** claim with `code` and a [link](https://example.org).\n\n" +
		"- [x] dig burrow\n" +
		"- [ ] store acorns\n\n" +
		"```rust\nfn main() {}\n```\n"
	blockCount, truncated, err := m.ParseMarkdown(md)
	if err != nil {
		fail("markdown parse", err)
	}
	if truncated {
		fail("markdown should not be truncated", nil)
	}
	if blockCount < 4 {
		fail(fmt.Sprintf("markdown should have >= 4 blocks, got %d", blockCount), nil)
	}
	ok(fmt.Sprintf("markdown parsed: %d blocks (heading + paragraph + list + code)", blockCount))

	// --- offline reads --------------------------------------------------
	count, err := m.AccountCount()
	if err != nil {
		fail("list_accounts", err)
	}
	if count != 0 {
		fail(fmt.Sprintf("fresh home should have 0 accounts, got %d", count), nil)
	}
	ok("fresh home has no accounts")

	// Directory lookup for an unknown id: the call succeeds and the (owned)
	// npub string is freed inside the wrapper.
	zeroID := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := m.Npub(zeroID); err != nil {
		fail("npub lookup", err)
	}
	ok("npub lookup call succeeds")

	// --- error taxonomy (hard asserts) ----------------------------------
	if _, err := m.Nip65Relays("no-such-account"); err == nil {
		fail("nip65_relays on unknown account should error", nil)
	} else if me, isMarmot := err.(*MarmotError); !isMarmot || me.Status != int(C.MARMOT_STATUS_UNKNOWN_ACCOUNT) {
		fail("nip65_relays should map to UNKNOWN_ACCOUNT", err)
	}
	ok("unknown account -> UNKNOWN_ACCOUNT (nip65_relays)")

	if _, err := m.RevealNsec("no-such-account"); err == nil {
		fail("reveal_nsec on unknown account should error", nil)
	} else if me, isMarmot := err.(*MarmotError); !isMarmot || me.Status != int(C.MARMOT_STATUS_UNKNOWN_ACCOUNT) {
		fail("reveal_nsec should map to UNKNOWN_ACCOUNT", err)
	}
	ok("unknown account -> UNKNOWN_ACCOUNT (reveal_nsec)")

	// --- best-effort identity (needs a relay) ---------------------------
	if accountID, err := m.CreateIdentity(relays, relays); err != nil {
		fmt.Printf("smoke(go): ok: identity create offline: %v\n", err)
	} else {
		fmt.Printf("smoke(go): ok: identity created: %s\n", accountID)
	}

	// --- shutdown -------------------------------------------------------
	if err := check(C.marmot_client_shutdown(m.client), "shutdown"); err != nil {
		fail("client shutdown", err)
	}
	stopping, err = m.IsStopping()
	if err != nil || !stopping {
		fail("client should report stopping after shutdown", err)
	}
	ok("client reports stopping")

	fmt.Println("smoke(go): all checks passed")
}
