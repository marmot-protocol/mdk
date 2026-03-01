/**
 * Deno FFI backend for libmdk.
 *
 * Auto-loads the native library from the bundled package paths.
 *
 * Requires: --allow-ffi
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

const TYPE_MAP: Record<string, NativeType> = {
  ptr: "pointer",
  cstr: "pointer",
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

function findLibrary(): string {
  const ext =
    Deno.build.os === "darwin"
      ? "dylib"
      : Deno.build.os === "windows"
        ? "dll"
        : "so";
  const base = Deno.build.os === "windows" ? `mdk.${ext}` : `libmdk.${ext}`;
  // `URL.pathname` on Windows yields `/C:/…`; strip the leading slash so
  // that path concatenation produces a valid native path.
  let pkgRoot = new URL(".", import.meta.url).pathname;
  if (Deno.build.os === "windows" && /^\/[A-Za-z]:/.test(pkgRoot)) {
    pkgRoot = pkgRoot.slice(1);
  }

  const arch = Deno.build.arch === "aarch64" ? "aarch64" : "x86_64";
  const platform =
    Deno.build.os === "darwin"
      ? `macos-${arch}`
      : Deno.build.os === "windows"
        ? `windows-${arch}`
        : `linux-${arch}`;

  const candidates = [
    // Packaged layout
    `${pkgRoot}../native/${platform}/${base}`,
    // Development: cargo build output
    `${pkgRoot}../../../target/release/${base}`,
    `${pkgRoot}../../../target/debug/${base}`,
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

function cstr(
  s: string | null | undefined,
): { buf: Uint8Array | null; ptr: Deno.PointerObject | null } {
  if (s === null || s === undefined) return { buf: null, ptr: null };
  const buf = encoder.encode(s + "\0");
  return { buf, ptr: Deno.UnsafePointer.of(buf) };
}

/**
 * Deno FFI backend — wraps the raw library handle and provides
 * helpers for string and pointer management.
 */
export class DenoFfi {
  #lib: Deno.DynamicLibrary<any>;

  constructor(libPath?: string) {
    const path = libPath ?? findLibrary();
    this.#lib = Deno.dlopen(path, toDenoSymbols(defs) as any);
  }

  get sym(): any {
    return this.#lib.symbols;
  }

  close(): void {
    this.#lib.close();
  }

  toCString(s: string | null | undefined) {
    return cstr(s);
  }

  readAndFreeString(pointer: Deno.PointerObject | null): string | null {
    if (!pointer) return null;
    const s = new Deno.UnsafePointerView(pointer).getCString();
    this.sym.mdk_string_free(pointer);
    return s;
  }

  readString(pointer: Deno.PointerObject | null): string | null {
    if (!pointer) return null;
    return new Deno.UnsafePointerView(pointer).getCString();
  }

  lastError(): string | null {
    const p = this.sym.mdk_last_error_message();
    return this.readAndFreeString(p);
  }

  bufferPtr(buf: Uint8Array): Deno.PointerObject | null {
    return Deno.UnsafePointer.of(buf);
  }

  allocOutPtr() {
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
      ptrPtr: Deno.UnsafePointer.of(ptrBuf),
      lenPtr: Deno.UnsafePointer.of(lenBuf),
      readAndFree() {
        const pVal = ptrBuf[0];
        const len = Number(lenBuf[0]);
        if (pVal === 0n) return null;
        const p = Deno.UnsafePointer.create(pVal);
        if (len === 0) {
          ffi.sym.mdk_bytes_free(p, 0n);
          return null;
        }
        const view = new Deno.UnsafePointerView(p!);
        const copy = new Uint8Array(len);
        view.copyInto(copy);
        ffi.sym.mdk_bytes_free(p, BigInt(len));
        return copy;
      },
    };
  }

  get nullptr(): null {
    return null;
  }
}
