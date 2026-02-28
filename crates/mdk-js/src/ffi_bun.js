/**
 * Bun FFI backend for libmdk.
 *
 * Loads the shared library via bun:ffi and provides a uniform
 * interface that the high-level Mdk class consumes.
 */
import { dlopen, suffix, ptr, CString, read, toArrayBuffer } from "bun:ffi";
import { symbols as defs } from "./symbols.js";

/** Map our shorthand types to bun:ffi type constants. */
const TYPE_MAP = {
  ptr: "ptr",
  cstr: "ptr",
  u8: "u8",
  u16: "u16",
  u32: "u32",
  u64: "u64",
  usize: "u64", // Bun has no native usize
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

/**
 * Open the libmdk shared library.
 *
 * @param {string} [libPath] — Path to libmdk. Defaults to searching
 *   standard locations relative to the workspace.
 * @returns {BunFfi}
 */
export function openLibrary(libPath) {
  const path = libPath ?? findLibrary();
  const lib = dlopen(path, toBunSymbols(defs));
  return new BunFfi(lib);
}

function findLibrary() {
  // Try common cargo output locations
  const base = `libmdk.${suffix}`;
  const candidates = [
    `../../target/release/${base}`,
    `../../target/debug/${base}`,
    `../mdk-cbindings/target/release/${base}`,
    `../mdk-cbindings/target/debug/${base}`,
    base, // system path
  ];
  for (const c of candidates) {
    try {
      // dlopen will throw if not found, so we just try the first
      // that the filesystem has
      const { existsSync } = require("fs");
      if (existsSync(c)) return c;
    } catch {
      // ignore
    }
  }
  return base;
}

/** Encode a JS string as a null-terminated Buffer and return its pointer. */
function cstr(s) {
  if (s === null || s === undefined) return null;
  const buf = Buffer.from(s + "\0", "utf8");
  return { buf, ptr: ptr(buf) };
}

/**
 * Bun FFI backend — wraps the raw library handle and provides
 * uniform helpers for string and pointer management.
 */
export class BunFfi {
  #lib;

  constructor(lib) {
    this.#lib = lib;
  }

  get sym() {
    return this.#lib.symbols;
  }

  close() {
    this.#lib.close();
  }

  // -- String helpers --

  /** Encode a JS string to a null-terminated C string (returns { buf, ptr }). */
  toCString(s) {
    return cstr(s);
  }

  /**
   * Read a C string from a pointer returned by Rust, then free it.
   *
   * @param {number} pointer — Bun represents pointers as numbers.
   * @returns {string}
   */
  readAndFreeString(pointer) {
    if (!pointer) return null;
    const s = new CString(pointer);
    this.sym.mdk_string_free(pointer);
    return s.toString();
  }

  /**
   * Read a C string from a pointer WITHOUT freeing.
   *
   * @param {number} pointer
   * @returns {string|null}
   */
  readString(pointer) {
    if (!pointer) return null;
    return new CString(pointer).toString();
  }

  /**
   * Read the last error message (thread-local, consumes it).
   * @returns {string|null}
   */
  lastError() {
    const p = this.sym.mdk_last_error_message();
    return this.readAndFreeString(p);
  }

  // -- Pointer helpers --

  /** Get a pointer to a Uint8Array. */
  bufferPtr(buf) {
    return ptr(buf);
  }

  /**
   * Allocate a pointer-sized buffer suitable for an out-parameter.
   * Returns { buf, ptr, read() }.
   */
  allocOutPtr() {
    // A pointer is 8 bytes on 64-bit
    const buf = new BigUint64Array(1);
    const p = ptr(buf);
    return {
      buf,
      ptr: p,
      /** Read the pointer value written by the C function. */
      read() {
        return Number(buf[0]);
      },
    };
  }

  /**
   * Allocate an out-parameter for a string pointer (char**).
   * Returns { buf, ptr, readAndFree(ffi) }.
   */
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

  /**
   * Allocate out-parameters for byte output (uint8_t** + usize*).
   */
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

  /** Null pointer constant. */
  get nullptr() {
    return null;
  }
}
