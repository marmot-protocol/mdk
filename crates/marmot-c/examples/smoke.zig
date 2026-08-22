// End-to-end smoke test for the marmot-c ABI from Zig.
//
// Imports the real marmot.h via @cImport, so the generated header is the
// single source of truth for signatures and struct layout. Exercises the
// same surface as examples/smoke.c: client lifecycle, error + last-error
// paths, a DEEP walk of the recursive Markdown DTO tree, offline reads,
// the error taxonomy, best-effort identity, and the free-the-root-only
// ownership rule.
//
// The calls are wrapped in a small `Marmot` type whose methods return Zig
// error unions (`MarmotError`); a helper maps any non-OK status to an
// error and stashes the thread-local last-error text. Cleanup uses
// `defer client.deinit()`, the natural Zig resource idiom. No naked
// out-parameter arrays leak into the top-level flow.
//
// Build & run (see c-smoke.sh for the canonical invocation):
//   zig build-exe examples/smoke.zig -I include -lc -fllvm \
//       target/debug/libmarmot_c.a -lm -lpthread -ldl -lunwind \
//       -femit-bin=smoke_zig
//   ./smoke_zig <fresh-empty-home-dir>
//
// `-fllvm` selects the LLVM backend (a standard ELF the loader accepts);
// `-lunwind` supplies the `_Unwind_*` symbols the Rust staticlib needs
// (gcc/clang link these implicitly, Zig does not).

const std = @import("std");

const c = @cImport({
    @cInclude("marmot.h");
});

// --- error handling -------------------------------------------------------

const MarmotError = error{
    NullPointer,
    UnknownAccount,
    Failed,
};

// Thread-local last-error detail, copied out of the C string the runtime
// hands us (and freed) so callers can print it after the fact.
var last_error_buf: [1024]u8 = undefined;
var last_error_len: usize = 0;

fn stashLastError() void {
    const msg = c.marmot_last_error_message();
    if (msg == null) {
        last_error_len = 0;
        return;
    }
    const s = std.mem.sliceTo(msg, 0);
    const n = @min(s.len, last_error_buf.len);
    @memcpy(last_error_buf[0..n], s[0..n]);
    last_error_len = n;
    c.marmot_string_free(msg);
}

fn lastError() []const u8 {
    return if (last_error_len == 0) "(no detail)" else last_error_buf[0..last_error_len];
}

// Map a raw status into a Zig error, capturing the runtime's detail text
// on the failure path. OK is the only success value.
fn mapStatus(st: c.MarmotStatus) MarmotError!void {
    if (st == c.MARMOT_STATUS_OK) return;
    stashLastError();
    if (st == c.MARMOT_STATUS_NULL_POINTER) return MarmotError.NullPointer;
    if (st == c.MARMOT_STATUS_UNKNOWN_ACCOUNT) return MarmotError.UnknownAccount;
    return MarmotError.Failed;
}

// --- idiomatic wrapper over the raw client -------------------------------

const Marmot = struct {
    client: *c.MarmotClient,

    fn open(root: [*c]const u8, relays: []const [*c]const u8) MarmotError!Marmot {
        var client: ?*c.MarmotClient = null;
        try mapStatus(c.marmot_client_new(root, relays.ptr, relays.len, &client));
        return .{ .client = client.? };
    }

    fn deinit(self: Marmot) void {
        c.marmot_client_free(self.client);
    }

    fn isStopping(self: Marmot) MarmotError!bool {
        var stopping: bool = false;
        try mapStatus(c.marmot_client_is_stopping(self.client, &stopping));
        return stopping;
    }

    fn start(self: Marmot) MarmotError!void {
        try mapStatus(c.marmot_client_start(self.client));
    }

    fn shutdown(self: Marmot) MarmotError!void {
        try mapStatus(c.marmot_client_shutdown(self.client));
    }

    fn parseMarkdown(self: Marmot, text: [*c]const u8) MarmotError!*c.MarmotMarkdownDocument {
        var doc: ?*c.MarmotMarkdownDocument = null;
        try mapStatus(c.marmot_parse_markdown(self.client, text, &doc));
        return doc.?;
    }

    fn listAccounts(self: Marmot) MarmotError!*c.MarmotAccountSummaryList {
        var list: ?*c.MarmotAccountSummaryList = null;
        try mapStatus(c.marmot_list_accounts(self.client, &list));
        return list.?;
    }

    // Absent directory entries resolve to OK with a NULL string; the
    // caller owns and frees whatever comes back.
    fn npub(self: Marmot, account_id_hex: [*c]const u8) MarmotError![*c]u8 {
        var out: [*c]u8 = null;
        try mapStatus(c.marmot_npub(self.client, account_id_hex, &out));
        return out;
    }

    fn nip65Relays(self: Marmot, account_ref: [*c]const u8) MarmotError!*c.MarmotStringList {
        var out: ?*c.MarmotStringList = null;
        try mapStatus(c.marmot_account_nip65_relays(self.client, account_ref, &out));
        return out.?;
    }

    fn revealNsec(self: Marmot, account_ref: [*c]const u8) MarmotError![*c]u8 {
        var out: [*c]u8 = null;
        try mapStatus(c.marmot_reveal_nsec(self.client, account_ref, &out));
        return out;
    }

    fn createIdentity(
        self: Marmot,
        def_relays: []const [*c]const u8,
        boot_relays: []const [*c]const u8,
    ) MarmotError!*c.MarmotAccountSummary {
        var out: ?*c.MarmotAccountSummary = null;
        try mapStatus(c.marmot_create_identity(
            self.client,
            def_relays.ptr,
            def_relays.len,
            boot_relays.ptr,
            boot_relays.len,
            &out,
        ));
        return out.?;
    }
};

// --- reporting helpers ----------------------------------------------------

fn fail(what: []const u8) noreturn {
    std.debug.print("smoke(zig): FAILED: {s}\n", .{what});
    std.process.exit(1);
}

fn expect(condition: bool, comptime what: []const u8) void {
    if (!condition) fail(what);
    std.debug.print("smoke(zig): ok: {s}\n", .{what});
}

// --- markdown walk (DEEP: reach into the tagged-union bodies) ------------

// Reconstruct the plain text of an inline run by concatenating its Text
// spans (and wrapping Code spans in backticks) — a walk of the inline
// tagged union, mirroring print_inline_text in smoke.c.
fn printInlineText(inlines: [*c]const c.MarmotMarkdownInline, len: usize) void {
    std.debug.print("\"", .{});
    for (inlines[0..len]) |inl| {
        if (inl.tag == c.MARMOT_MARKDOWN_INLINE_TEXT) {
            std.debug.print("{s}", .{inl.unnamed_0.TEXT.content});
        } else if (inl.tag == c.MARMOT_MARKDOWN_INLINE_CODE) {
            std.debug.print("`{s}`", .{inl.unnamed_0.CODE.content});
        }
    }
    std.debug.print("\"", .{});
}

// Classify each top-level block by its tag and reach into the union body,
// mirroring walk_markdown in smoke.c. Returns the heading count seen.
fn walkMarkdown(doc: *const c.MarmotMarkdownDocument) usize {
    var headings: usize = 0;
    for (doc.blocks[0..doc.blocks_len], 0..) |block, i| {
        if (block.tag == c.MARMOT_MARKDOWN_BLOCK_HEADING) {
            headings += 1;
            const heading = block.unnamed_0.HEADING;
            std.debug.print("smoke(zig):   block {d}: heading (h{d}) ", .{ i, heading.level });
            printInlineText(heading.inlines, heading.inlines_len);
            std.debug.print("\n", .{});
        } else if (block.tag == c.MARMOT_MARKDOWN_BLOCK_PARAGRAPH) {
            std.debug.print(
                "smoke(zig):   block {d}: paragraph ({d} inlines)\n",
                .{ i, block.unnamed_0.PARAGRAPH.inlines_len },
            );
        } else if (block.tag == c.MARMOT_MARKDOWN_BLOCK_CODE_BLOCK) {
            const info = block.unnamed_0.CODE_BLOCK.info;
            if (info == null) {
                std.debug.print("smoke(zig):   block {d}: code block (lang=)\n", .{i});
            } else {
                std.debug.print("smoke(zig):   block {d}: code block (lang={s})\n", .{ i, info });
            }
        } else if (block.tag == c.MARMOT_MARKDOWN_BLOCK_LIST_BLOCK) {
            std.debug.print(
                "smoke(zig):   block {d}: list with {d} items\n",
                .{ i, block.unnamed_0.LIST_BLOCK.items_len },
            );
        } else {
            std.debug.print("smoke(zig):   block {d}: other\n", .{i});
        }
    }
    return headings;
}

pub fn main() void {
    var args = std.process.args();
    _ = args.next(); // argv[0]
    const home = args.next() orelse {
        std.debug.print("usage: smoke <fresh-home-dir>\n", .{});
        std.process.exit(2);
    };

    // --- argument validation + NULL-free discipline (no client) ---------
    const no_relays = [_][*c]const u8{};
    if (Marmot.open(null, &no_relays)) |m| {
        m.deinit();
        fail("NULL root_path should have been rejected");
    } else |err| {
        expect(err == MarmotError.NullPointer, "NULL root_path rejected");
        expect(last_error_len > 0, "NULL root_path sets last-error");
    }

    // NULL is a no-op for every free function.
    c.marmot_client_free(null);
    c.marmot_string_free(null);
    c.marmot_account_summary_list_free(null);
    c.marmot_markdown_document_free(null);
    std.debug.print("smoke(zig): ok: NULL frees are no-ops\n", .{});

    // --- construct + lifecycle ------------------------------------------
    const relays = [_][*c]const u8{"wss://relay.example.org"};
    const client = Marmot.open(home.ptr, &relays) catch {
        // Headless environments may lack a platform keychain; a documented
        // limitation, not an ABI defect.
        std.debug.print("smoke(zig): SKIP: client_new failed: {s}\n", .{lastError()});
        return;
    };
    defer client.deinit();
    std.debug.print("smoke(zig): ok: client constructed\n", .{});

    const stopping_before = client.isStopping() catch |e| fail(@errorName(e));
    expect(!stopping_before, "client not stopping");

    // start() may fail offline (dial-safety rejects unreachable relays);
    // that still exercises the start + error path. Either outcome is fine.
    if (client.start()) {
        std.debug.print("smoke(zig): ok: client started\n", .{});
    } else |_| {
        std.debug.print("smoke(zig): ok: client start offline: {s}\n", .{lastError()});
    }

    // --- Markdown: parse + DEEP walk of the recursive DTO tree ----------
    const md =
        "# Marmot\n\n" ++
        "A **bold** claim with `code` and a [link](https://example.org).\n\n" ++
        "- [x] dig burrow\n" ++
        "- [ ] store acorns\n\n" ++
        "```rust\nfn main() {}\n```\n";
    const doc = client.parseMarkdown(md) catch |e| fail(@errorName(e));
    defer c.marmot_markdown_document_free(doc);
    expect(!doc.truncated, "markdown not truncated");
    expect(doc.blocks_len >= 4, "markdown has heading + paragraph + list + code");
    const headings = walkMarkdown(doc);
    expect(headings == 1, "walked tree found exactly one heading");

    // --- offline reads --------------------------------------------------
    const accounts = client.listAccounts() catch |e| fail(@errorName(e));
    defer c.marmot_account_summary_list_free(accounts);
    expect(accounts.len == 0, "fresh home has no accounts");

    // A directory lookup for an unknown id resolves to absent (NULL out).
    const unknown_id = "0000000000000000000000000000000000000000000000000000000000000000";
    const npub = client.npub(unknown_id) catch |e| fail(@errorName(e));
    std.debug.print("smoke(zig): ok: npub lookup for absent id resolves\n", .{});
    c.marmot_string_free(npub);

    // --- error taxonomy (hard asserts) ----------------------------------
    if (client.nip65Relays("no-such-account")) |list| {
        c.marmot_string_list_free(list);
        fail("nip65_relays on unknown account should error");
    } else |err| {
        expect(err == MarmotError.UnknownAccount, "unknown account -> UnknownAccount");
    }

    if (client.revealNsec("no-such-account")) |nsec| {
        c.marmot_string_free(nsec);
        fail("reveal_nsec on unknown account should error");
    } else |err| {
        expect(err == MarmotError.UnknownAccount, "reveal_nsec unknown account -> UnknownAccount");
    }

    // --- best-effort identity (needs a relay) ---------------------------
    if (client.createIdentity(&relays, &relays)) |summary| {
        std.debug.print("smoke(zig): ok: identity created: {s}\n", .{summary.account_id_hex});
        c.marmot_account_summary_free(summary);
    } else |_| {
        std.debug.print("smoke(zig): ok: identity create offline: {s}\n", .{lastError()});
    }

    // --- shutdown -------------------------------------------------------
    client.shutdown() catch |e| fail(@errorName(e));
    std.debug.print("smoke(zig): ok: client shutdown\n", .{});
    const stopping_after = client.isStopping() catch |e| fail(@errorName(e));
    expect(stopping_after, "client reports stopping");

    std.debug.print("smoke(zig): all checks passed\n", .{});
}
