/**
 * Bun FFI backend for libmdk.
 *
 * Auto-loads the native library from the bundled package paths.
 */
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { dlopen, suffix, ptr, CString, toArrayBuffer } from "bun:ffi";
import { symbols as defs } from "./symbols.js";

/** Map our shorthand types to bun:ffi type constants. */
const TYPE_MAP = {
  ptr: "ptr",
  cstr: "ptr",
  u8: "u8",
  u16: "u16",
  u32: "u32",
  u64: "u64",
  usize: "u64",
  bool: "bool",
  i32: "i32",
  void: "void",
};

function toBunSymbols(defs) {
  const out = {};
  for (const [name, def] of Object.entries(defs)) {
    out[name] = {
      args: def.params.map((t) => TYPE_MAP[t]),
      returns: TYPE_MAP[def.result],
    };
  }
  return out;
}

function findLibrary() {
  const base = `libmdk.${suffix}`;
  const pkgRoot = dirname(new URL(import.meta.url).pathname);

  // Platform directory name used in the packaged layout
  const platform =
    process.platform === "darwin"
      ? "macos-aarch64"
      : process.platform === "win32"
        ? "windows-x86_64"
        : "linux-x86_64";

  const candidates = [
    // Packaged layout (CI publishes here)
    join(pkgRoot, "..", "native", platform, base),
    // Development: cargo build output
    join(pkgRoot, "..", "..", "..", "target", "release", base),
    join(pkgRoot, "..", "..", "..", "target", "debug", base),
    // Monorepo sibling
    join(pkgRoot, "..", "..", "mdk-cbindings", "target", "release", base),
    join(pkgRoot, "..", "..", "mdk-cbindings", "target", "debug", base),
  ];

  for (const c of candidates) {
    if (existsSync(c)) return c;
  }

  // Last resort: let the linker search system paths
  return base;
}

/** Encode a JS string as a null-terminated Buffer and return its pointer. */
function cstr(s) {
  if (s === null || s === undefined) return { buf: null, ptr: null };
  const buf = Buffer.from(s + "\0", "utf8");
  return { buf, ptr: ptr(buf) };
}

/**
 * Bun FFI backend — wraps the raw library handle and provides
 * helpers for string and pointer management.
 */
export class BunFfi {
  #lib;

  constructor(libPath) {
    const path = libPath ?? findLibrary();
    this.#lib = dlopen(path, toBunSymbols(defs));
  }

  get sym() {
    return this.#lib.symbols;
  }

  close() {
    this.#lib.close();
  }

  toCString(s) {
    return cstr(s);
  }

  readAndFreeString(pointer) {
    if (!pointer) return null;
    const s = new CString(pointer);
    this.sym.mdk_string_free(pointer);
    return s.toString();
  }

  readString(pointer) {
    if (!pointer) return null;
    return new CString(pointer).toString();
  }

  lastError() {
    const p = this.sym.mdk_last_error_message();
    return this.readAndFreeString(p);
  }

  bufferPtr(buf) {
    return ptr(buf);
  }

  allocOutPtr() {
    const buf = new BigUint64Array(1);
    const p = ptr(buf);
    return {
      buf,
      ptr: p,
      read() {
        return Number(buf[0]);
      },
    };
  }

  allocOutString() {
    const out = this.allocOutPtr();
    const ffi = this;
    return {
      ...out,
      readAndFree() {
        const p = out.read();
        return ffi.readAndFreeString(p);
      },
    };
  }

  allocOutBytes() {
    const ptrBuf = new BigUint64Array(1);
    const lenBuf = new BigUint64Array(1);
    const ffi = this;
    return {
      ptrPtr: ptr(ptrBuf),
      lenPtr: ptr(lenBuf),
      readAndFree() {
        const p = Number(ptrBuf[0]);
        const len = Number(lenBuf[0]);
        if (!p || len === 0) return null;
        const ab = toArrayBuffer(p, 0, len);
        const copy = new Uint8Array(ab.slice(0));
        ffi.sym.mdk_bytes_free(p, len);
        return copy;
      },
    };
  }

  get nullptr() {
    return null;
  }
}
