/**
 * MDK bindings for Bun.
 *
 * The native library is loaded automatically from the bundled package.
 *
 * @example
 * ```js
 * import { Mdk } from "mdk-js";
 *
 * const mdk = Mdk.createUnencrypted("/tmp/test.db");
 * const groups = mdk.getGroups();
 * console.log(groups);
 * mdk.close();
 * ```
 */
import { BunFfi } from "./ffi_bun.js";
import { setBackend } from "./mdk.js";

const _backend = new BunFfi();
setBackend(_backend);

export { Mdk, MdkError, ErrorCode, prepareGroupImage, decryptGroupImage, deriveUploadKeypair } from "./mdk.js";
