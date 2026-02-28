/**
 * Deno FFI backend for libmdk.
 *
 * Loads the shared library via Deno.dlopen and provides a uniform
 * interface that the high-level Mdk class consumes.
 *
 * Requires: --allow-ffi --unstable-ffi
 */
import { symbols as defs } from "./symbols.js";

type NativeType =
  | "i8"
  | "i16"
  | "i32"
  | "u8"
  | "u16"
  | "u32"
  | "u64"
  | "usize"
  | "isize"
  | "f32"
  | "f64"
  | "bool"
  | "void"
  | "pointer"
  | "buffer";

/** Map our shorthand types to Deno FFI types. */
const TYPE_MAP: Record<string, NativeType> = {
  ptr: "pointer",
  cstr: "buffer",
  u8: "u8",
  u16: "u16",
  u32: "u32",
  u64: "u64",
  usize: "usize",
  bool: "bool",
  i32: "i32",
  void: "void",
};

function toDenoSymbols(
  defs: Record<string, { params: string[]; result: string }>,
) {
  const out: Record<
    string,
    { parameters: NativeType[]; result: NativeType }
  > = {};
  for (const [name, def] of Object.entries(defs)) {
    out[name] = {
      parameters: def.params.map((t) => TYPE_MAP[t]),
      result: TYPE_MAP[def.result],
    };
  }
  return out;
}

/**
 * Open the libmdk shared library.
 *
 * @param libPath — Path to libmdk. Defaults to searching standard locations.
 */
export function openLibrary(libPath?: string): DenoFfi {
  const path = libPath ?? findLibrary();
  const lib = Deno.dlopen(path, toDenoSymbols(defs) as any);
  return new DenoFfi(lib);
}

function findLibrary(): string {
  const ext =
    Deno.build.os === "darwin"
      ? "dylib"
      : Deno.build.os === "windows"
        ? "dll"
        : "so";
  const base = `libmdk.${ext}`;
  const candidates = [
    `../../target/release/${base}`,
    `../../target/debug/${base}`,
    base,
  ];
  for (const c of candidates) {
    try {
      Deno.statSync(c);
      return c;
    } catch {
      // continue
    }
  }
  return base;
}

const encoder = new TextEncoder();

/** Encode a JS string as a null-terminated Uint8Array. */
function cstr(s: string | null | undefined): Uint8Array | null {
  if (s === null || s === undefined) return null;
  return encoder.encode(s + "\0");
}

/**
 * Deno FFI backend — wraps the raw library handle and provides
 * uniform helpers for string and pointer management.
 */
export class DenoFfi {
  #lib: Deno.DynamicLibrary<any>;

  constructor(lib: Deno.DynamicLibrary<any>) {
    this.#lib = lib;
  }

  get sym(): any {
    return this.#lib.symbols;
  }

  close(): void {
    this.#lib.close();
  }

  // -- String helpers --

  /** Encode a JS string to a null-terminated buffer. */
  toCString(s: string | null | undefined): {
    buf: Uint8Array | null;
    ptr: Deno.PointerObject | null;
  } {
    const buf = cstr(s);
    if (!buf) return { buf: null, ptr: null };
    return { buf, ptr: Deno.UnsafePointer.of(buf) };
  }

  /**
   * Read a C string from a pointer returned by Rust, then free it.
   * IMPORTANT: must read BEFORE freeing on Deno (no clone safety).
   */
  readAndFreeString(pointer: Deno.PointerObject | null): string | null {
    if (!pointer) return null;
    const s = new Deno.UnsafePointerView(pointer).getCString();
    this.sym.mdk_string_free(pointer);
    return s;
  }

  /** Read a C string from a pointer WITHOUT freeing. */
  readString(pointer: Deno.PointerObject | null): string | null {
    if (!pointer) return null;
    return new Deno.UnsafePointerView(pointer).getCString();
  }

  /** Read the last error message (thread-local, consumes it). */
  lastError(): string | null {
    const p = this.sym.mdk_last_error_message();
    return this.readAndFreeString(p);
  }

  // -- Pointer helpers --

  /** Get a pointer to a Uint8Array. */
  bufferPtr(buf: Uint8Array): Deno.PointerObject | null {
    return Deno.UnsafePointer.of(buf);
  }

  /**
   * Allocate a pointer-sized buffer suitable for an out-parameter.
   */
  allocOutPtr(): {
    buf: BigUint64Array;
    ptr: Deno.PointerObject | null;
    read: () => Deno.PointerObject | null;
  } {
    const buf = new BigUint64Array(1);
    const p = Deno.UnsafePointer.of(buf);
    return {
      buf,
      ptr: p,
      read() {
        const val = buf[0];
        if (val === 0n) return null;
        return Deno.UnsafePointer.create(val);
      },
    };
  }

  /**
   * Allocate an out-parameter for a string pointer (char**).
   */
  allocOutString(): {
    buf: BigUint64Array;
    ptr: Deno.PointerObject | null;
    readAndFree: () => string | null;
  } {
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
  allocOutBytes(): {
    ptrPtr: Deno.PointerObject | null;
    lenPtr: Deno.PointerObject | null;
    readAndFree: () => Uint8Array | null;
  } {
    const ptrBuf = new BigUint64Array(1);
    const lenBuf = new BigUint64Array(1);
    const ffi = this;
    return {
      ptrPtr: Deno.UnsafePointer.of(ptrBuf),
      lenPtr: Deno.UnsafePointer.of(lenBuf),
      readAndFree() {
        const pVal = ptrBuf[0];
        const len = Number(lenBuf[0]);
        if (pVal === 0n || len === 0) return null;
        const p = Deno.UnsafePointer.create(pVal);
        const view = new Deno.UnsafePointerView(p!);
        const copy = new Uint8Array(len);
        view.copyInto(copy);
        ffi.sym.mdk_bytes_free(p, BigInt(len));
        return copy;
      },
    };
  }

  /** Null pointer constant. */
  get nullptr(): null {
    return null;
  }
}
