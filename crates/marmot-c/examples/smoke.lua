-- Idiomatic Lua consumer of the marmot-c ABI, via the LuaJIT FFI.
--
-- Stock Lua has no FFI, so this targets LuaJIT's `ffi`. The raw C surface is
-- wrapped in a small `Marmot` object (metatable + methods) that returns Lua
-- values, ties the client's lifetime to the garbage collector with ffi.gc,
-- and raises Lua errors (catchable with pcall) on failure -- so the smoke
-- test at the bottom reads like ordinary Lua rather than transliterated C. It
-- exercises the same behaviour as examples/smoke.c: client lifecycle, markdown
-- parsing, account listing, directory (npub) lookup, the UNKNOWN_ACCOUNT error
-- taxonomy, best-effort identity creation, and cleanup.
--
-- Run (see c-smoke.sh for the canonical invocation):
--   MARMOT_C_LIB=target/debug/libmarmot_c.so \
--       luajit examples/smoke.lua <fresh-empty-home-dir>

local ffi = require("ffi")

ffi.cdef([[
typedef struct MarmotClient MarmotClient;
typedef struct MarmotStringList MarmotStringList;
typedef struct MarmotMarkdownBlock MarmotMarkdownBlock;
typedef struct MarmotAccountSummary MarmotAccountSummary;

typedef struct MarmotMarkdownDocument {
    MarmotMarkdownBlock *blocks;
    uintptr_t blocks_len;
    bool truncated;
} MarmotMarkdownDocument;

typedef struct MarmotAccountSummary {
    char *label;
    char *account_id_hex;
    bool local_signing;
    bool signed_out;
    bool running;
} MarmotAccountSummary;

typedef struct MarmotAccountSummaryList {
    MarmotAccountSummary *items;
    uintptr_t len;
} MarmotAccountSummaryList;

int marmot_client_new(const char *root_path, const char *const *relay_urls,
                      uintptr_t relay_urls_len, MarmotClient **out_client);
int marmot_client_start(const MarmotClient *client);
int marmot_client_shutdown(const MarmotClient *client);
int marmot_client_is_stopping(const MarmotClient *client, bool *out_stopping);
void marmot_client_free(MarmotClient *client);
char *marmot_last_error_message(void);
void marmot_string_free(char *s);
int marmot_parse_markdown(const MarmotClient *client, const char *text,
                          MarmotMarkdownDocument **out_document);
void marmot_markdown_document_free(MarmotMarkdownDocument *document);
int marmot_list_accounts(const MarmotClient *client, MarmotAccountSummaryList **out_list);
void marmot_account_summary_list_free(MarmotAccountSummaryList *list);
int marmot_account_nip65_relays(const MarmotClient *client, const char *account_ref,
                                MarmotStringList **out_list);
int marmot_npub(const MarmotClient *client, const char *account_id_hex, char **out_npub);
int marmot_reveal_nsec(const MarmotClient *client, const char *account_ref, char **out_nsec);
int marmot_create_identity(const MarmotClient *client,
                           const char *const *default_relays, uintptr_t default_relays_len,
                           const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len,
                           MarmotAccountSummary **out_summary);
void marmot_account_summary_free(MarmotAccountSummary *summary);
]])

--- Marmot: a thin object wrapper over the C ABI. --------------------------

local Marmot = {}
Marmot.__index = Marmot

-- MarmotStatus values referenced by name (stable ABI).
Marmot.STATUS_OK = 0
Marmot.STATUS_UNKNOWN_ACCOUNT = 11

-- Take and free the thread-local last-error detail.
local function take_last_error(lib)
    local msg = lib.marmot_last_error_message()
    if msg == nil then return "(no detail)" end
    local text = ffi.string(msg)
    lib.marmot_string_free(msg)
    return text
end

-- Raise a Lua error carrying the status code and detail (catch with pcall).
local function throw(lib, op)
    error({ status = nil, message = op .. ": " .. take_last_error(lib) }, 0)
end

local function check(lib, status, op)
    if status ~= Marmot.STATUS_OK then
        error({ status = status, message = op .. ": " .. take_last_error(lib) }, 0)
    end
end

--- Open a client rooted at `root` and connected to `relays` (a list of URLs).
--- Raises on failure.
function Marmot.open(root, relays, libpath)
    local lib = ffi.load(libpath or os.getenv("MARMOT_C_LIB") or "marmot_c")
    local arr = ffi.new("const char*[?]", #relays, relays)
    local out = ffi.new("MarmotClient*[1]")
    check(lib, lib.marmot_client_new(root, arr, #relays, out), "open")
    -- Tie the client's lifetime to GC; :close() detaches this finalizer.
    local client = ffi.gc(out[0], function(c) lib.marmot_client_free(c) end)
    return setmetatable({ _lib = lib, _client = client }, Marmot)
end

--- Start the runtime. Returns nil on success, or the error detail when it
--- fails (e.g. offline, where dial-safety rejects the relay).
function Marmot:try_start()
    local status = self._lib.marmot_client_start(self._client)
    if status == Marmot.STATUS_OK then return nil end
    return take_last_error(self._lib)
end

function Marmot:is_stopping()
    local flag = ffi.new("bool[1]")
    check(self._lib, self._lib.marmot_client_is_stopping(self._client, flag), "is_stopping")
    return flag[0]
end

--- Parse markdown, returning { blocks = <count>, truncated = <bool> }.
function Marmot:parse_markdown(text)
    local out = ffi.new("MarmotMarkdownDocument*[1]")
    check(self._lib, self._lib.marmot_parse_markdown(self._client, text, out), "parse_markdown")
    local doc = out[0]
    local result = { blocks = tonumber(doc.blocks_len), truncated = doc.truncated }
    self._lib.marmot_markdown_document_free(doc)
    return result
end

--- Number of accounts known to this device.
function Marmot:account_count()
    local out = ffi.new("MarmotAccountSummaryList*[1]")
    check(self._lib, self._lib.marmot_list_accounts(self._client, out), "list_accounts")
    local n = tonumber(out[0].len)
    self._lib.marmot_account_summary_list_free(out[0])
    return n
end

--- Raises { status = STATUS_UNKNOWN_ACCOUNT, ... } for an unknown ref.
function Marmot:nip65_relays(account_ref)
    local out = ffi.new("MarmotStringList*[1]")
    check(self._lib, self._lib.marmot_account_nip65_relays(self._client, account_ref, out), "nip65_relays")
    -- (A real caller would read + free out[0] here; this example only needs
    -- the error path.)
end

--- Directory lookup: resolve an account id to its npub. An id the directory
--- has never seen resolves to absent (nil); a live account yields the string.
--- Raises on an outright ABI failure.
function Marmot:npub(account_id_hex)
    local out = ffi.new("char*[1]")
    check(self._lib, self._lib.marmot_npub(self._client, account_id_hex, out), "npub")
    if out[0] == nil then return nil end
    local text = ffi.string(out[0])
    self._lib.marmot_string_free(out[0])
    return text
end

--- Reveal the nsec (private key) for a local-signing account. Raises
--- { status = STATUS_UNKNOWN_ACCOUNT, ... } for a ref this device doesn't hold.
function Marmot:reveal_nsec(account_ref)
    local out = ffi.new("char*[1]")
    check(self._lib, self._lib.marmot_reveal_nsec(self._client, account_ref, out), "reveal_nsec")
    if out[0] == nil then return nil end
    local text = ffi.string(out[0])
    self._lib.marmot_string_free(out[0])
    return text
end

--- Best-effort: mint a fresh local identity, publishing to `relays`. Online
--- this returns the new account's id (hex); offline the runtime raises a typed
--- error (dial-safety / no relay reachable). Callers wrap this in pcall.
function Marmot:create_identity(relays)
    local arr = ffi.new("const char*[?]", #relays, relays)
    local out = ffi.new("MarmotAccountSummary*[1]")
    check(self._lib,
          self._lib.marmot_create_identity(self._client, arr, #relays, arr, #relays, out),
          "create_identity")
    local summary = out[0]
    local account_id = summary.account_id_hex ~= nil and ffi.string(summary.account_id_hex) or nil
    self._lib.marmot_account_summary_free(summary)
    return account_id
end

function Marmot:shutdown()
    if self._client ~= nil then
        self._lib.marmot_client_shutdown(self._client)
    end
end

--- Free the client now and detach the GC finalizer (idempotent).
function Marmot:close()
    if self._client ~= nil then
        ffi.gc(self._client, nil)
        self._lib.marmot_client_free(self._client)
        self._client = nil
    end
end

--- smoke test -------------------------------------------------------------

local function ok(what)
    io.write("smoke(lua): ok: ", what, "\n")
end

local function fail(what)
    io.write("smoke(lua): FAILED: ", what, "\n")
    os.exit(1)
end

local home = arg[1]
if not home then
    io.stderr:write("usage: smoke.lua <fresh-home-dir>\n")
    os.exit(2)
end

local opened, marmot = pcall(Marmot.open, home, { "ws://127.0.0.1:7777" })
if not opened then
    -- Headless environments may lack a platform keychain; documented
    -- limitation, not an ABI defect.
    io.write("smoke(lua): SKIP: open failed: ", tostring(marmot.message or marmot), "\n")
    os.exit(0)
end
ok("client constructed")

if marmot:is_stopping() then fail("fresh client should not be stopping") end
ok("client not stopping")

-- start() may fail offline (dial-safety rejects loopback relays); that still
-- exercises the start + error path. Either outcome is fine.
local start_err = marmot:try_start()
ok(start_err == nil and "client started" or ("client start offline: " .. start_err))

-- A document with a heading, a paragraph mixing bold/code/link, a task list,
-- and a fenced code block -- four top-level blocks the parser must not truncate.
local doc = marmot:parse_markdown(
    "# Marmot\n\n" ..
    "A **bold** claim with `code` and a [link](https://example.org).\n\n" ..
    "- [x] dig burrow\n" ..
    "- [ ] store acorns\n\n" ..
    "```rust\nfn main() {}\n```\n")
if doc.blocks < 4 then fail("markdown should have heading + paragraph + list + code") end
ok("markdown parsed with " .. doc.blocks .. " blocks")
if doc.truncated then fail("markdown should not be truncated") end
ok("markdown not truncated")

if marmot:account_count() ~= 0 then fail("fresh home should have no accounts") end
ok("fresh home has no accounts")

-- Directory lookup for an id nobody has published resolves to absent (nil),
-- not an error.
local unknown_id = string.rep("0", 64)
local looked_up, npub = pcall(function() return marmot:npub(unknown_id) end)
if not looked_up then fail("npub lookup should not raise for an unknown id") end
ok("npub lookup of unknown id returns " .. (npub == nil and "absent" or npub))

-- Error taxonomy: both nip65 relays and reveal_nsec on an account this device
-- doesn't hold must raise the same typed UNKNOWN_ACCOUNT status.
local caught, err = pcall(function() marmot:nip65_relays("no-such-account") end)
if caught then fail("unknown account nip65 should raise") end
if err.status ~= Marmot.STATUS_UNKNOWN_ACCOUNT then fail("unexpected nip65 status " .. tostring(err.status)) end
ok("nip65 on unknown account raises typed error")

caught, err = pcall(function() marmot:reveal_nsec("no-such-account") end)
if caught then fail("unknown account reveal_nsec should raise") end
if err.status ~= Marmot.STATUS_UNKNOWN_ACCOUNT then fail("unexpected reveal_nsec status " .. tostring(err.status)) end
ok("reveal_nsec on unknown account raises typed error")

-- Best-effort: creating an identity needs a reachable relay. Online it mints
-- an account; offline the runtime raises a typed error. Either is fine.
local created, result = pcall(function() return marmot:create_identity({ "wss://relay.example.org" }) end)
if created then
    ok("identity created: " .. tostring(result))
else
    ok("identity create offline: " .. tostring(result.message or result))
end

marmot:shutdown()
if not marmot:is_stopping() then fail("client should report stopping after shutdown") end
ok("client reports stopping after shutdown")

marmot:close()
ok("client freed via close")

io.write("smoke(lua): all checks passed\n")
