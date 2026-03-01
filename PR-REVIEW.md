# PR Review: C/Zig/JS Bindings

Brutal review of all ~5,832 lines added in this PR. Nothing is too small.

---

## C Bindings (Rust) -- `mdk-cbindings`

### 1. `#![deny(unsafe_code)]` immediately followed by `#![allow(unsafe_code)]`

**`lib.rs:12-15`**

```rust
#![deny(unsafe_code)]
// We allow `unsafe` only in explicitly marked blocks — the deny is overridden
// per-function with `#[allow(unsafe_code)]` where FFI requires it.
#![allow(unsafe_code)]
```

This is safety theater. You deny unsafe, then immediately allow it. The net effect is `#![allow(unsafe_code)]`. The comment describes a system that doesn't exist -- there are no per-function `#[allow(unsafe_code)]` attributes anywhere in the codebase. Either keep the deny and put `#[allow(unsafe_code)]` on each `extern "C"` fn, or delete both attributes.

### 2. Duplicated `UpdateGroupResultJson` and serialization logic

**`groups.rs` and `messages.rs`** both define their own `UpdateGroupResultJson` struct and their own serialization function (`serialize_update_result` vs `serialize_core_update`). They're almost character-for-character identical. One returns `Result<String, MdkError>`, the other returns `Result<serde_json::Value, MdkError>`. Put the shared struct and logic in `types.rs` and parameterize the return type, or just make one that returns `Value` and let the caller `.to_string()` it.

### 3. `ffi_catch` and `ffi_try` are defined but `ffi_catch` is never called directly

In `types.rs`, `ffi_catch` exists and `ffi_try` calls it, and `ffi_try_unwind_safe` calls `ffi_try`. But `ffi_catch` is only ever used through `ffi_try` which is only ever used through `ffi_try_unwind_safe`. Three layers of wrapper to get to one thing. The intermediate `ffi_try` function adds nothing -- it's just `ffi_catch` with a closure that maps `Ok(())` to `MdkError::Ok`. Collapse these.

### 4. `AssertUnwindSafe` blanket usage without justification

Every single FFI function uses `ffi_try_unwind_safe` which blindly wraps the closure in `AssertUnwindSafe`. The comment says "All our FFI functions take `&MdkHandle` which is behind a `Mutex` -- any poisoning is caught at the lock site." That's not what `UnwindSafe` is about. `UnwindSafe` is about whether the state is consistent after a panic. The `AssertUnwindSafe` is fine pragmatically for an FFI boundary, but the comment is misleading about *why* it's fine.

### 5. Every single function does the same null-check boilerplate

This pattern is repeated 25+ times:

```rust
if h.is_null() {
    return Err(error::null_pointer("handle"));
}
if out_json.is_null() {
    return Err(error::null_pointer("out_json"));
}
let handle = unsafe { &*h };
```

That's 6-7 lines of boilerplate in every function. Make a helper or a macro.

### 6. `media.rs` -- `.as_ref().clone()` on encrypted data

```rust
encrypted_data: prepared.encrypted_data.as_ref().clone(),
```

Clones the entire encrypted image data into a `Vec<u8>` just to put it in a JSON serialization struct. Then it gets JSON-serialized, creating yet another copy. For a multi-megabyte image, three copies in memory simultaneously: the original, the clone, and the JSON string.

### 7. `media.rs` -- Secret key material returned as hex string in JSON

```rust
upload_secret_key: prepared.upload_keypair.secret_key().to_secret_hex(),
```

A **secret key** gets serialized into a regular `String` inside a struct with no `ZeroizeOnDrop`. It will sit in memory until the allocator reuses that page. The AGENTS.md security rules say "Use `Secret<T>` wrapper for sensitive values" and "Derive `ZeroizeOnDrop` for types containing key material." This violates both.

### 8. `ConfigOverrides::into_core` -- Manual field-by-field defaulting

```rust
fn into_core(self) -> CoreMdkConfig {
    let d = CoreMdkConfig::default();
    CoreMdkConfig {
        max_event_age_secs: self.max_event_age_secs.unwrap_or(d.max_event_age_secs),
        ...
    }
}
```

If `CoreMdkConfig` ever gets a new field, this silently uses the struct default with no compile-time guard. The real fix is to use serde's `#[serde(default)]` on `CoreMdkConfig` directly and just deserialize into it. The serialization framework already does this work.

### 9. `epoch_snapshot_retention` -- Silent truncation

```rust
epoch_snapshot_retention: self
    .epoch_snapshot_retention
    .map(|v| v as usize)
    .unwrap_or(d.epoch_snapshot_retention),
```

The core config has this as `usize` while the JSON config has it as `u32`. Type mismatch that reveals the manual mapping is doing too much.

### 10. No tests whatsoever in the Rust C bindings crate

Zero. Not a single `#[test]`. Not a single integration test. This is an FFI boundary -- the most dangerous code in the entire stack -- with `unsafe` code all over the place, pointer arithmetic, `Box::from_raw`, `CString::from_raw`, and not one test verifying any of it works correctly or doesn't leak memory.

---

## JavaScript Bindings -- `mdk-js`

### 11. Module-level singleton backend

```js
let _ffi = null;
export function setBackend(backend) { _ffi = backend; }
```

`index.js` and `mod.ts` both call `setBackend()` at module evaluation time as a side effect. If someone imports from both entry points (accidentally), the second import silently replaces the first backend. No warning, no error. Also means the native library is loaded as soon as you import *anything* from it -- even just the `ErrorCode` enum.

### 12. Platform detection is hardcoded and wrong

```js
const platform =
    process.platform === "darwin"
      ? "macos-aarch64"
      : process.platform === "win32"
        ? "windows-x86_64"
        : "linux-x86_64";
```

What about `linux-aarch64`? ARM Linux is a thing (Raspberry Pi, AWS Graviton). This silently loads the x86_64 binary on ARM Linux, which will crash with an inscrutable dlopen error. Same in Deno. For macOS, it hardcodes `aarch64` -- Intel Macs still exist. Should check `process.arch` / `Deno.build.arch`.

### 13. `allocOutPtr` in Bun uses `Number()` on BigInt, losing precision

```js
allocOutPtr() {
    const buf = new BigUint64Array(1);
    ...
    return {
      ...
      read() {
        return Number(buf[0]);
      },
    };
  }
```

`Number()` on a `BigInt` loses precision above `Number.MAX_SAFE_INTEGER` (2^53). Pointers on 64-bit systems can exceed this. The Deno version uses `Deno.UnsafePointer.create(val)` which handles this correctly. Inconsistent safety between backends.

### 14. No GC safety / no prevent-double-free / no use-after-close guard

```js
close() {
    if (this.#handle) {
      ffi().sym.mdk_free(this.#handle);
      this.#handle = null;
    }
  }
```

No `FinalizationRegistry` fallback -- if someone forgets `close()`, the native handle leaks forever. Nothing prevents using the `Mdk` instance after `close()` -- every method just passes `this.#handle` (now `null`) to the C side, getting an opaque null-pointer error instead of a clear "already closed" error in JS.

### 15. `toCString` buffers may be GC'd before the C call completes

```js
const cGid = ffi().toCString(mlsGroupId);
return callWithJsonOut(ffi().sym.mdk_get_group, this.#handle, cGid.ptr);
```

The `cGid` object holds a reference to the buffer, but only `.ptr` is passed to the FFI call. Depending on JS engine optimizations, the buffer backing `cGid.ptr` could theoretically be GC'd between when the pointer is extracted and when the native function reads it. Keep the buffer alive explicitly.

### 16. JSON double-encoding for key package events

```js
const cKp = f.toCString(JSON.stringify(keyPackageEvents.map((e) => JSON.stringify(e))));
```

JSON-stringifying each event object, putting those strings into an array, then JSON-stringifying the array. The C side receives a JSON array of JSON strings, each of which it then parses individually. Two parse passes per event. Just pass a JSON array of event objects and parse them directly. Wasted CPU at both ends.

---

## Zig Bindings -- `mdk-zig`

### 17. Every function allocates and frees null-terminated copies of every string argument

```zig
const c_gid = try sliceToC(self.allocator, mls_group_id);
defer freeCStr(self.allocator, c_gid, mls_group_id.len);
```

This pattern appears in every single function. For `createGroup` with 6 string parameters, that's 6 allocations and 6 frees per call. Could accept `[:0]const u8` (sentinel-terminated slices) instead, letting the caller provide null-terminated strings and skipping the copy entirely. Or use a stack-based buffer for short strings.

### 18. `configToJson` -- Hand-rolled JSON serializer

```zig
fn configToJson(allocator: std.mem.Allocator, cfg: ?Config) ...
```

Manual JSON serializer using inline for loops and string formatting. Brittle pattern. Zig's `std.json` exists -- use it.

### 19. `var out: [*c]u8 = undefined;` -- uninitialized out pointer

Throughout the Zig bindings:

```zig
var out: [*c]u8 = undefined;
try check(raw.mdk_get_groups(self.handle, &out));
```

If the C function fails, `out` is still `undefined`. Technically fine since `check()` returns the error. But if someone refactors and adds code between `check` and `return`, they'll read an `undefined` pointer. Initialize to `null`:

```zig
var out: [*c]u8 = null;
```

### 20. Tests are pathetically thin

```zig
test "CString slice and deinit" {
    const msg = lastErrorMessage();
    try std.testing.expect(msg == null);
}
```

Zero testing of any actual MDK functionality through the Zig bindings. No `initUnencrypted` -> `getGroups` -> `deinit` round-trip. Nothing that exercises the C library through the Zig wrapper.

---

## CI / Workflow

### 21. Three nearly identical publish jobs

`publish-cbindings`, `publish-zig`, and `publish-js` are ~95% identical. They all checkout code, download artifacts, extract version, assemble package, checkout target repo, configure git, copy files, commit and push, and tag on release. ~270 lines of YAML that should be a reusable workflow or composite action. Fixing a bug in one means remembering to fix it in the other two.

### 22. `grep -E` version extraction is fragile

```yaml
VERSION=$(grep -E '^version\s*=' crates/mdk-cbindings/Cargo.toml | head -1 | sed -E 's/version\s*=\s*"([^"]+)"/\1/')
```

If someone uses `workspace = true` for the version field, this breaks silently. Use `cargo metadata --format-version=1 | jq ...` which actually understands Cargo's workspace resolution.

### 23. Windows OpenSSL via vcpkg is a time bomb

```yaml
vcpkg install openssl:x64-windows-static
```

No version pinning on vcpkg or OpenSSL. CI will randomly break when vcpkg updates OpenSSL to a version that's incompatible with your Rust dependencies.

### 24. `2>/dev/null || true` hides real failures

```yaml
cp ffi-native-all/ffi-native-ubuntu-latest/libmdk.so cbindings-package/lib/linux-x86_64/ 2>/dev/null || true
```

If the build succeeded but the artifact path changed, or the upload step silently failed, this swallows the error. You'll publish a package with a missing `.so` and no one will know until a user reports it.

---

## General / Cross-cutting

### 25. No `mip04` feature gate on media functions in C bindings

`media.rs` imports from `mdk_core::extension::group_image` unconditionally. The `Cargo.toml` has a `mip04` feature that gates `mdk-core/mip04`, but `media.rs` is always compiled -- no `#[cfg(feature = "mip04")]`. The JS and Zig bindings also unconditionally expose the media functions. Should be feature-gated consistently.

### 26. The generated header `mdk.h` is checked into git

`include/mdk.h` is auto-generated by `build.rs` via cbindgen, but it's also checked into the repository. Every doc comment change creates noise in diffs, someone can edit the header and the build will overwrite their changes, and there's a perpetual risk of the checked-in header being stale. Either generate it as part of CI only, or add it to `.gitignore`.

### 27. `mdk_bytes_free` -- Potential unsoundness with `len == 0`

```rust
pub unsafe extern "C" fn mdk_bytes_free(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, len)) });
    }
}
```

If someone passes `data = non-null, len = 0`, the free is skipped and the allocation leaks. `Box::from_raw` with a zero-length slice is valid in Rust, so the `len > 0` guard is arguably wrong -- it prevents freeing zero-length allocations.

### 28. Thread-local error storage is not documented as non-thread-safe for callbacks

The `LAST_ERROR` thread-local means the error message is only available on the thread that made the call. If someone calls MDK from one thread and checks the error from another (common in callback-based architectures), they'll get `null`. Standard C pattern, but not documented anywhere in the header or README.

### 29. README for C bindings references a repo that doesn't exist yet

```markdown
These bindings use native FFI ... to call the [C bindings](https://github.com/marmot-protocol/mdk-cbindings) directly
```

The repo URL is referenced before the CI has created and published to it. Dead link on first publish.

---

## Priority Summary

The biggest structural issues:

1. **Zero tests for the FFI boundary** -- The most dangerous code (raw pointers, `Box::from_raw`, `CString::from_raw`) has zero test coverage
2. **Massive code duplication** -- Between the three publish jobs, between the UpdateGroupResult serialization in two files, and between the null-check boilerplate in every function
3. **The JS double-JSON-encoding** -- Parsing JSON strings inside JSON arrays is burning CPU for no reason
4. **Platform detection that silently fails on ARM** -- This will bite someone
5. **Secret key material in non-zeroed memory** -- Violates the project's own security rules
