/**
 * High-level MDK wrapper that works with both Bun and Deno FFI backends.
 *
 * The FFI backend is set once at module load via `setBackend()` — called
 * automatically by the runtime-specific entry point (index.js / mod.ts).
 * Users never interact with the backend directly.
 */

/** @type {import("./ffi_bun.js").BunFfi | import("./ffi_deno.ts").DenoFfi | null} */
let _ffi = null;

/**
 * Set the FFI backend for this module.  Called once by the entry point.
 * @param {object} backend
 */
export function setBackend(backend) {
  if (_ffi !== null) {
    throw new Error(
      "MDK: backend already set. " +
      "This usually means both index.js (Bun) and mod.ts (Deno) were imported.",
    );
  }
  _ffi = backend;
}

/** Return the active backend, throwing if not yet initialised. */
function ffi() {
  if (!_ffi) {
    throw new Error(
      "MDK not initialised. Import from the runtime-specific entry point " +
        '(e.g. import { Mdk } from "mdk-js" for Bun, or import { Mdk } from "./mod.ts" for Deno).',
    );
  }
  return _ffi;
}

/** Error thrown by MDK operations. */
export class MdkError extends Error {
  /** @param {number} code  @param {string|null} detail */
  constructor(code, detail) {
    super(detail ?? `MDK error (code ${code})`);
    this.name = "MdkError";
    this.code = code;
  }
}

export const ErrorCode = Object.freeze({
  OK: 0,
  STORAGE: 1,
  MDK: 2,
  INVALID_INPUT: 3,
  NULL_POINTER: 4,
});

function check(code) {
  if (code !== ErrorCode.OK) {
    const detail = ffi().lastError();
    throw new MdkError(code, detail);
  }
}

/**
 * Call an FFI function that writes a string to an out-pointer.
 * NOTE: All toCString() buffers must be kept alive (referenced by local
 * variables) until the FFI call returns. Do not extract .ptr from a
 * toCString result and discard the wrapper before the call completes.
 */
function callWithStringOut(fn, ...args) {
  const f = ffi();
  const out = f.allocOutString();
  try {
    const code = fn(...args, out.ptr);
    check(code);
    return out.readAndFree();
  } catch (e) {
    out.readAndFree();
    throw e;
  }
}

/**
 * Call an FFI function that writes JSON to an out-pointer and parses the result.
 * See callWithStringOut for buffer lifetime notes.
 */
function callWithJsonOut(fn, ...args) {
  const s = callWithStringOut(fn, ...args);
  return s ? JSON.parse(s) : null;
}

// ---------------------------------------------------------------------------
// Mdk class
// ---------------------------------------------------------------------------

export class Mdk {
  #handle;

  /** @param {*} handle — opaque MdkHandle pointer */
  constructor(handle) {
    this.#handle = handle;
    _leakRegistry.register(this, new Error().stack, this);
  }

  /** @throws {Error} if the instance has been closed */
  #assertOpen() {
    if (this.#handle === null) {
      throw new Error("MDK instance already closed");
    }
  }

  // -- Constructors ---------------------------------------------------------

  /**
   * Create an MDK instance with encrypted storage (platform keyring).
   *
   * @param {string} dbPath
   * @param {string} serviceId
   * @param {string} dbKeyId
   * @param {object|null} [config]
   * @returns {Mdk}
   */
  static create(dbPath, serviceId, dbKeyId, config = null) {
    const f = ffi();
    const cPath = f.toCString(dbPath);
    const cSvc = f.toCString(serviceId);
    const cKey = f.toCString(dbKeyId);
    const cCfg = config ? f.toCString(JSON.stringify(config)) : { ptr: f.nullptr };
    const out = f.allocOutPtr();

    check(f.sym.mdk_new(cPath.ptr, cSvc.ptr, cKey.ptr, cCfg.ptr, out.ptr));
    return new Mdk(out.read());
  }

  /**
   * Create an MDK instance with a directly provided encryption key.
   *
   * @param {string} dbPath
   * @param {Uint8Array} key — 32-byte encryption key
   * @param {object|null} [config]
   * @returns {Mdk}
   */
  static createWithKey(dbPath, key, config = null) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error("createWithKey: key must be a Uint8Array of exactly 32 bytes");
    }
    const f = ffi();
    const cPath = f.toCString(dbPath);
    const cCfg = config ? f.toCString(JSON.stringify(config)) : { ptr: f.nullptr };
    const out = f.allocOutPtr();

    check(f.sym.mdk_new_with_key(cPath.ptr, f.bufferPtr(key), key.length, cCfg.ptr, out.ptr));
    return new Mdk(out.read());
  }

  /**
   * Create an MDK instance with unencrypted storage.
   * WARNING: only for development/testing.
   *
   * @param {string} dbPath
   * @param {object|null} [config]
   * @returns {Mdk}
   */
  static createUnencrypted(dbPath, config = null) {
    const f = ffi();
    const cPath = f.toCString(dbPath);
    const cCfg = config ? f.toCString(JSON.stringify(config)) : { ptr: f.nullptr };
    const out = f.allocOutPtr();

    check(f.sym.mdk_new_unencrypted(cPath.ptr, cCfg.ptr, out.ptr));
    return new Mdk(out.read());
  }

  /** Free the MDK handle. Must be called when done. */
  close() {
    if (this.#handle !== null) {
      _leakRegistry.unregister(this);
      ffi().sym.mdk_free(this.#handle);
      this.#handle = null;
    }
  }

  // -- Key Packages ---------------------------------------------------------

  /**
   * Create a key package (no NIP-70 protected tag).
   * @param {string} pubkey — hex public key
   * @param {string[]} relays — relay URLs
   * @returns {{ key_package: string, tags: string[][], hash_ref: number[] }}
   */
  createKeyPackage(pubkey, relays) {
    this.#assertOpen();
    const f = ffi();
    const cPk = f.toCString(pubkey);
    const cRelays = f.toCString(JSON.stringify(relays));
    return callWithJsonOut(f.sym.mdk_create_key_package, this.#handle, cPk.ptr, cRelays.ptr);
  }

  /**
   * Create a key package with options.
   * @param {string} pubkey
   * @param {string[]} relays
   * @param {boolean} isProtected — add NIP-70 protected tag
   */
  createKeyPackageWithOptions(pubkey, relays, isProtected) {
    this.#assertOpen();
    const f = ffi();
    const cPk = f.toCString(pubkey);
    const cRelays = f.toCString(JSON.stringify(relays));
    return callWithJsonOut(
      f.sym.mdk_create_key_package_with_options,
      this.#handle, cPk.ptr, cRelays.ptr, isProtected,
    );
  }

  /**
   * Parse and validate a key package from a Nostr event.
   * @param {object} event — Nostr event object
   * @returns {string}
   */
  parseKeyPackage(event) {
    this.#assertOpen();
    const f = ffi();
    const cEv = f.toCString(JSON.stringify(event));
    return callWithStringOut(f.sym.mdk_parse_key_package, this.#handle, cEv.ptr);
  }

  // -- Groups ---------------------------------------------------------------

  /** Get all groups. @returns {object[]} */
  getGroups() {
    this.#assertOpen();
    return callWithJsonOut(ffi().sym.mdk_get_groups, this.#handle);
  }

  /**
   * Get a single group by MLS group ID.
   * @param {string} mlsGroupId — hex
   * @returns {object|null}
   */
  getGroup(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    return callWithJsonOut(ffi().sym.mdk_get_group, this.#handle, cGid.ptr);
  }

  /**
   * Get members of a group.
   * @param {string} mlsGroupId
   * @returns {string[]} — hex public keys
   */
  getMembers(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    return callWithJsonOut(ffi().sym.mdk_get_members, this.#handle, cGid.ptr);
  }

  /**
   * Get group IDs needing a self-update.
   * @param {number} thresholdSecs
   * @returns {string[]} — hex group IDs
   */
  groupsNeedingSelfUpdate(thresholdSecs) {
    this.#assertOpen();
    return callWithJsonOut(ffi().sym.mdk_groups_needing_self_update, this.#handle, thresholdSecs);
  }

  /**
   * Create a new group.
   * @param {string} creatorPk — hex public key
   * @param {object[]} keyPackageEvents — Nostr event objects
   * @param {string} name
   * @param {string} description
   * @param {string[]} relays — relay URLs
   * @param {string[]} admins — hex public keys
   */
  createGroup(creatorPk, keyPackageEvents, name, description, relays, admins) {
    this.#assertOpen();
    const f = ffi();
    const cPk = f.toCString(creatorPk);
    const cKp = f.toCString(JSON.stringify(keyPackageEvents));
    const cName = f.toCString(name);
    const cDesc = f.toCString(description);
    const cRelays = f.toCString(JSON.stringify(relays));
    const cAdmins = f.toCString(JSON.stringify(admins));
    return callWithJsonOut(
      f.sym.mdk_create_group,
      this.#handle, cPk.ptr, cKp.ptr, cName.ptr, cDesc.ptr, cRelays.ptr, cAdmins.ptr,
    );
  }

  /**
   * Add members to a group.
   * @param {string} mlsGroupId
   * @param {object[]} keyPackageEvents
   */
  addMembers(mlsGroupId, keyPackageEvents) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cKp = f.toCString(JSON.stringify(keyPackageEvents));
    return callWithJsonOut(f.sym.mdk_add_members, this.#handle, cGid.ptr, cKp.ptr);
  }

  /**
   * Remove members from a group.
   * @param {string} mlsGroupId
   * @param {string[]} pubkeys — hex public keys
   */
  removeMembers(mlsGroupId, pubkeys) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cPks = f.toCString(JSON.stringify(pubkeys));
    return callWithJsonOut(f.sym.mdk_remove_members, this.#handle, cGid.ptr, cPks.ptr);
  }

  /**
   * Update group data.
   * @param {string} mlsGroupId
   * @param {object} update — { name?, description?, image_hash?, relays?, admins? }
   */
  updateGroupData(mlsGroupId, update) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cUpd = f.toCString(JSON.stringify(update));
    return callWithJsonOut(f.sym.mdk_update_group_data, this.#handle, cGid.ptr, cUpd.ptr);
  }

  /** Perform a self-update (key rotation). @param {string} mlsGroupId */
  selfUpdate(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    return callWithJsonOut(ffi().sym.mdk_self_update, this.#handle, cGid.ptr);
  }

  /** Leave a group. @param {string} mlsGroupId */
  leaveGroup(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    return callWithJsonOut(ffi().sym.mdk_leave_group, this.#handle, cGid.ptr);
  }

  /** Merge pending commit. @param {string} mlsGroupId */
  mergePendingCommit(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    check(ffi().sym.mdk_merge_pending_commit(this.#handle, cGid.ptr));
  }

  /** Clear pending commit. @param {string} mlsGroupId */
  clearPendingCommit(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    check(ffi().sym.mdk_clear_pending_commit(this.#handle, cGid.ptr));
  }

  /** Sync group metadata from MLS. @param {string} mlsGroupId */
  syncGroupMetadata(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    check(ffi().sym.mdk_sync_group_metadata(this.#handle, cGid.ptr));
  }

  /**
   * Get relays for a group.
   * @param {string} mlsGroupId
   * @returns {string[]}
   */
  getRelays(mlsGroupId) {
    this.#assertOpen();
    const cGid = ffi().toCString(mlsGroupId);
    return callWithJsonOut(ffi().sym.mdk_get_relays, this.#handle, cGid.ptr);
  }

  // -- Messages -------------------------------------------------------------

  /**
   * Create a message in a group.
   * @param {string} mlsGroupId
   * @param {string} senderPk — hex
   * @param {string} content
   * @param {number} kind — Nostr event kind
   * @param {string[][]|null} [tags]
   */
  createMessage(mlsGroupId, senderPk, content, kind, tags = null) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cPk = f.toCString(senderPk);
    const cContent = f.toCString(content);
    const cTags = tags ? f.toCString(JSON.stringify(tags)) : { ptr: f.nullptr };
    return callWithJsonOut(
      f.sym.mdk_create_message,
      this.#handle, cGid.ptr, cPk.ptr, cContent.ptr, kind, cTags.ptr,
    );
  }

  /**
   * Process an incoming MLS message.
   * @param {object} event — Nostr event
   * @returns {{ type: string, message?, result?, mls_group_id?, reason? }}
   */
  processMessage(event) {
    this.#assertOpen();
    const cEv = ffi().toCString(JSON.stringify(event));
    return callWithJsonOut(ffi().sym.mdk_process_message, this.#handle, cEv.ptr);
  }

  /**
   * Get messages for a group.
   * @param {string} mlsGroupId
   * @param {{ limit?: number, offset?: number, sortOrder?: string }} [opts]
   * @returns {object[]}
   */
  getMessages(mlsGroupId, opts = {}) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cSort = opts.sortOrder ? f.toCString(opts.sortOrder) : { ptr: f.nullptr };
    return callWithJsonOut(
      f.sym.mdk_get_messages,
      this.#handle, cGid.ptr, opts.limit ?? 0, opts.offset ?? 0, cSort.ptr,
    );
  }

  /**
   * Get a single message by event ID.
   * @param {string} mlsGroupId
   * @param {string} eventId — hex
   * @returns {object|null}
   */
  getMessage(mlsGroupId, eventId) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cEid = f.toCString(eventId);
    return callWithJsonOut(f.sym.mdk_get_message, this.#handle, cGid.ptr, cEid.ptr);
  }

  /**
   * Get the most recent message.
   * @param {string} mlsGroupId
   * @param {"created_at_first"|"processed_at_first"} sortOrder
   */
  getLastMessage(mlsGroupId, sortOrder) {
    this.#assertOpen();
    const f = ffi();
    const cGid = f.toCString(mlsGroupId);
    const cSort = f.toCString(sortOrder);
    return callWithJsonOut(f.sym.mdk_get_last_message, this.#handle, cGid.ptr, cSort.ptr);
  }

  // -- Welcomes -------------------------------------------------------------

  /**
   * Get pending welcomes.
   * @param {{ limit?: number, offset?: number }} [opts]
   */
  getPendingWelcomes(opts = {}) {
    this.#assertOpen();
    return callWithJsonOut(
      ffi().sym.mdk_get_pending_welcomes,
      this.#handle, opts.limit ?? 0, opts.offset ?? 0,
    );
  }

  /** Get a welcome by event ID. @param {string} eventId */
  getWelcome(eventId) {
    this.#assertOpen();
    const cEid = ffi().toCString(eventId);
    return callWithJsonOut(ffi().sym.mdk_get_welcome, this.#handle, cEid.ptr);
  }

  /**
   * Process a welcome message.
   * @param {string} wrapperEventId — hex event ID
   * @param {object} rumor — unsigned event object
   */
  processWelcome(wrapperEventId, rumor) {
    this.#assertOpen();
    const f = ffi();
    const cWid = f.toCString(wrapperEventId);
    const cRumor = f.toCString(JSON.stringify(rumor));
    return callWithJsonOut(f.sym.mdk_process_welcome, this.#handle, cWid.ptr, cRumor.ptr);
  }

  /**
   * Accept a welcome.
   * @param {object} welcome
   */
  acceptWelcome(welcome) {
    this.#assertOpen();
    const cJson = ffi().toCString(JSON.stringify(welcome));
    check(ffi().sym.mdk_accept_welcome(this.#handle, cJson.ptr));
  }

  /**
   * Decline a welcome.
   * @param {object} welcome
   */
  declineWelcome(welcome) {
    this.#assertOpen();
    const cJson = ffi().toCString(JSON.stringify(welcome));
    check(ffi().sym.mdk_decline_welcome(this.#handle, cJson.ptr));
  }
}

// Leak detection: warn if an Mdk instance is GC'd without close().
const _leakRegistry = new FinalizationRegistry((hint) => {
  console.warn(
    `MDK: handle was garbage-collected without calling close() (created at: ${hint}). ` +
    "This leaks native memory. Always call mdk.close() when done.",
  );
});

// ---------------------------------------------------------------------------
// Free functions (media)
// ---------------------------------------------------------------------------

/**
 * Prepare a group image for upload.
 * @param {Uint8Array} data — raw image bytes
 * @param {string} mime — e.g. "image/png"
 */
export function prepareGroupImage(data, mime) {
  const f = ffi();
  const cMime = f.toCString(mime);
  return callWithJsonOut(
    f.sym.mdk_prepare_group_image,
    f.bufferPtr(data), data.length, cMime.ptr,
  );
}

/**
 * Decrypt a group image.
 * @param {Uint8Array} data — encrypted data
 * @param {Uint8Array|null} expectedHash — 32-byte SHA-256 hash (null to skip)
 * @param {Uint8Array} key — 32-byte key
 * @param {Uint8Array} nonce — 12-byte nonce
 * @returns {Uint8Array}
 */
export function decryptGroupImage(data, expectedHash, key, nonce) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error("decryptGroupImage: key must be a Uint8Array of exactly 32 bytes");
  }
  if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
    throw new Error("decryptGroupImage: nonce must be a Uint8Array of exactly 12 bytes");
  }
  if (expectedHash != null && (!(expectedHash instanceof Uint8Array) || expectedHash.length !== 32)) {
    throw new Error("decryptGroupImage: expectedHash must be a Uint8Array of exactly 32 bytes or null");
  }
  const f = ffi();
  const out = f.allocOutBytes();
  try {
    check(f.sym.mdk_decrypt_group_image(
      f.bufferPtr(data), data.length,
      expectedHash ? f.bufferPtr(expectedHash) : f.nullptr,
      expectedHash ? expectedHash.length : 0,
      f.bufferPtr(key), key.length,
      f.bufferPtr(nonce), nonce.length,
      out.ptrPtr, out.lenPtr,
    ));
    return out.readAndFree();
  } catch (e) {
    out.readAndFree();
    throw e;
  }
}

/**
 * Derive an upload keypair from an image key.
 * @param {Uint8Array} key — 32-byte key
 * @param {number} version
 * @returns {string} — hex-encoded secret key
 */
export function deriveUploadKeypair(key, version) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error("deriveUploadKeypair: key must be a Uint8Array of exactly 32 bytes");
  }
  const f = ffi();
  return callWithStringOut(
    f.sym.mdk_derive_upload_keypair,
    f.bufferPtr(key), key.length, version,
  );
}
