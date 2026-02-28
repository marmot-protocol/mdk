/**
 * MDK bindings for Deno.
 *
 * Requires: --allow-ffi
 *
 * @example
 * ```ts
 * import { openLibrary, Mdk } from "./mod.ts";
 *
 * const ffi = openLibrary();
 * const mdk = Mdk.createUnencrypted(ffi, "/tmp/test.db");
 *
 * const groups = mdk.getGroups();
 * console.log(groups);
 *
 * mdk.close();
 * ffi.close();
 * ```
 */
export { openLibrary } from "./ffi_deno.ts";
export { Mdk, MdkError, ErrorCode, prepareGroupImage, decryptGroupImage, deriveUploadKeypair } from "./mdk.js";
