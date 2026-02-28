/**
 * MDK bindings for Deno.
 *
 * The native library is loaded automatically from the bundled package.
 * Requires: --allow-ffi
 *
 * @example
 * ```ts
 * import { Mdk } from "./mod.ts";
 *
 * const mdk = Mdk.createUnencrypted("/tmp/test.db");
 * const groups = mdk.getGroups();
 * console.log(groups);
 * mdk.close();
 * ```
 */
import { DenoFfi } from "./ffi_deno.ts";
import { setBackend } from "./mdk.js";

const _backend = new DenoFfi();
setBackend(_backend);

export { Mdk, MdkError, ErrorCode, prepareGroupImage, decryptGroupImage, deriveUploadKeypair } from "./mdk.js";
