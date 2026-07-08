# marmot-c

Stable C ABI for the Marmot app runtime. Exposes the same surface as the UniFFI bindings
(`crates/marmot-uniffi` — accounts, groups, messaging, media, timeline, notifications, push,
audit, relay health, agent text streams, markdown parsing) to consumers that cannot pull in a
UniFFI runtime: C/C++ applications, Zig, Odin, and raw FFI from Go, Lua, and friends.

## Build

```sh
# Library + checked-in header
cargo build -p marmot-c --release
# → target/release/libmarmot_c.so (cdylib) and libmarmot_c.a (staticlib)
# → header at crates/marmot-c/include/marmot.h

# Full packaged artifact set (libs + header + pkg-config) into output/
./crates/marmot-c/c-bindings.sh
```

## Quick start

```c
#include <marmot.h>

const char *relays[] = { "wss://relay.example.org" };
MarmotClient *client = NULL;
MarmotStatus st = marmot_client_new("/home/me/.marmot", relays, 1, &client);
if (st != MARMOT_STATUS_OK) {
    char *msg = marmot_last_error_message();
    fprintf(stderr, "marmot: %s\n", msg ? msg : "(no detail)");
    marmot_string_free(msg);
    return 1;
}
marmot_client_start(client);
/* ... marmot_send_text(client, ...), subscriptions, ... */
marmot_client_shutdown(client);
marmot_client_free(client);
```

Rules of the road (also in the header comment):

- Fallible calls return `MarmotStatus`; `MARMOT_STATUS_OK` is `0`. Detail text for the calling
  thread's most recent failure: `marmot_last_error_message()` (free with `marmot_string_free`).
- Returned structs are freed **only** with their matching `marmot_*_free`, which deep-frees every
  field. Never free fields individually, never free twice. Inputs are always borrowed.
- Async runtime work happens on an embedded tokio runtime; calls block the calling thread.
  Subscriptions offer blocking `*_next` with a timeout, or callback registration (callbacks run on
  runtime worker threads; item pointers are valid only during the call).

## Linking

pkg-config (after `c-bindings.sh`, or point `PKG_CONFIG_PATH` at `output/`):

```sh
cc app.c $(pkg-config --cflags --libs marmot-c)
```

Minimal CMake:

```cmake
find_library(MARMOT_C marmot_c PATHS ${MARMOT_OUTPUT_DIR})
target_include_directories(app PRIVATE ${MARMOT_OUTPUT_DIR}/include)
target_link_libraries(app PRIVATE ${MARMOT_C})
```

The static library additionally needs the usual Rust system deps (`-lm -lpthread -ldl` on Linux).

## Examples

`examples/` holds one worked end-to-end consumer per language. Each drives a
realistic slice of the runtime — argument validation and NULL-free discipline,
client lifecycle, markdown parsing, offline account/directory reads, the typed
error taxonomy (`UNKNOWN_ACCOUNT`), and best-effort identity creation — behind
an abstraction idiomatic to its language (real error values/exceptions and the
language's cleanup idiom, with the out-parameter plumbing hidden):

- `smoke.c` — C11, static archive. Also walks the recursive Markdown DTO tree
  (tagged-union blocks/inlines) — the reference for that navigation.
- `smoke.zig` — Zig `@cImport`, static archive; `Marmot` struct + error unions;
  deep markdown walk.
- `smoke.nim` — Nim `importc`, static archive; object + `MarmotError` + `=destroy`
  RAII; deep markdown walk.
- `smoke.go` — Go cgo, static archive; wrapper type returning `error`; markdown
  at document level (cgo's anonymous-union access is unergonomic).
- `smoke.odin` — Odin hand-declared `foreign`, shared library; `Marmot` struct +
  `or_return`; document-level markdown.
- `smoke.lua` — LuaJIT `ffi`, shared library; metatable object, `ffi.gc` cleanup,
  `pcall`-catchable errors; document-level markdown.
- `smoke.php` — PHP FFI, shared library; `Marmot` class with exceptions, destructor
  cleanup, and a `@method`-typed FFI view for static analysis; document-level
  markdown.

The deep tagged-union walk lives in the header-import languages (C, Zig, Nim)
where the compiler guarantees the union layout; hand-declared consumers keep
markdown at the document level rather than risk transcribing the recursive
layout by hand.

`c-smoke.sh` builds and runs every one of these (C under valgrind when
available); each language is skipped if its toolchain is absent. Run the whole
set with `just c-smoke`. Between them they cover both linkage models (static
archive and shared object) and both binding styles (header import and
hand-declared decls) — the raw-FFI matrix a stable C ABI has to satisfy.

## Notes

- The account store uses the platform keychain (same as the UniFFI constructor). Headless servers
  without a secret service will fail account creation; a non-keychain store is a planned follow-up.
- `group_id_hex` parameters are opaque variable-length MLS group ids (hex), not 32-byte Nostr
  route ids.
- Header regeneration: `just c-header` (cbindgen). The header is checked in and CI-gated.
