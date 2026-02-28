/**
 * MDK bindings for Bun.
 *
 * @example
 * ```js
 * import { openLibrary, Mdk } from "mdk-js";
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
export { openLibrary } from "./ffi_bun.js";
export { Mdk, MdkError, ErrorCode, prepareGroupImage, decryptGroupImage, deriveUploadKeypair } from "./mdk.js";
