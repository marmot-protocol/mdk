/**
 * High-level MDK wrapper that works with both Bun and Deno FFI backends.
 *
 * All methods accept/return plain JS values (strings, objects, arrays).
 * JSON serialisation is handled transparently.
 */

/** Error thrown by MDK operations. */
export class MdkError extends Error {
  /** @param {number} code  @param {string|null} detail */
  constructor(code, detail) {
    super(detail ?? `MDK error (code ${code})`);
    this.name = "MdkError";
    this.code = code;
  }
}

// Error code constants matching the C enum.
export const ErrorCode = Object.freeze({
  OK: 0,
  STORAGE: 1,
  MDK: 2,
  INVALID_INPUT: 3,
  NULL_POINTER: 4,
});

/**
 * Check an FFI return code; throw MdkError on failure.
 * @param {object} ffi — the backend instance
 * @param {number} code — MdkError enum value
 */
function check(ffi, code) {
  if (code !== ErrorCode.OK) {
    const detail = ffi.lastError();
    throw new MdkError(code, detail);
  }
}

/**
 * Call an FFI function that writes its result into a char** out-parameter.
 * Returns the result as a JS string.
 */
function callWithStringOut(ffi, fn, ...args) {
  const out = ffi.allocOutString();
  const code = fn(...args, out.ptr);
  check(ffi, code);
  return out.readAndFree();
}

/**
 * Call an FFI function that writes its result into a char** out-parameter.
 * Parses the result as JSON.
 */
function callWithJsonOut(ffi, fn, ...args) {
  const s = callWithStringOut(ffi, fn, ...args);
  return s ? JSON.parse(s) : null;
}

// ---------------------------------------------------------------------------
// Mdk class
// ---------------------------------------------------------------------------

export class Mdk {
  #ffi;
  #handle;

  /**
   * @param {object} ffi — BunFfi or DenoFfi instance
   * @param {*} handle — opaque MdkHandle pointer
   */
  constructor(ffi, handle) {
    this.#ffi = ffi;
    this.#handle = handle;
  }

  /** @returns {*} the raw handle pointer (for advanced use) */
  get handle() {
    return this.#handle;
  }

  /** @returns {object} the FFI backend (for advanced use) */
  get ffi() {
    return this.#ffi;
  }

  // -- Constructors (static) ------------------------------------------------

  /**
   * Create an MDK instance with encrypted storage (platform keyring).
   *
   * @param {object} ffi — BunFfi or DenoFfi
   * @param {string} dbPath
   * @param {string} serviceId
   * @param {string} dbKeyId
   * @param {object|null} [config]
   * @returns {Mdk}
   */
  static create(ffi, dbPath, serviceId, dbKeyId, config = null) {
    const cPath = ffi.toCString(dbPath);
    const cSvc = ffi.toCString(serviceId);
    const cKey = ffi.toCString(dbKeyId);
    const cCfg = config ? ffi.toCString(JSON.stringify(config)) : { ptr: ffi.nullptr };
    const out = ffi.allocOutPtr();

    const code = ffi.sym.mdk_new(cPath.ptr, cSvc.ptr, cKey.ptr, cCfg.ptr, out.ptr);
    check(ffi, code);
    return new Mdk(ffi, out.read());
  }

  /**
   * Create an MDK instance with a directly provided encryption key.
   *
   * @param {object} ffi
   * @param {string} dbPath
   * @param {Uint8Array} key — 32-byte encryption key
   * @param {object|null} [config]
   * @returns {Mdk}
   */
  static createWithKey(ffi, dbPath, key, config = null) {
    const cPath = ffi.toCString(dbPath);
    const cCfg = config ? ffi.toCString(JSON.stringify(config)) : { ptr: ffi.nullptr };
    const out = ffi.allocOutPtr();

    const code = ffi.sym.mdk_new_with_key(
      cPath.ptr,
      ffi.bufferPtr(key),
      key.length,
      cCfg.ptr,
      out.ptr,
    );
    check(ffi, code);
    return new Mdk(ffi, out.read());
  }

  /**
   * Create an MDK instance with unencrypted storage.
   * WARNING: only for development/testing.
   *
   * @param {object} ffi
   * @param {string} dbPath
   * @param {object|null} [config]
   * @returns {Mdk}
   */
  static createUnencrypted(ffi, dbPath, config = null) {
    const cPath = ffi.toCString(dbPath);
    const cCfg = config ? ffi.toCString(JSON.stringify(config)) : { ptr: ffi.nullptr };
    const out = ffi.allocOutPtr();

    const code = ffi.sym.mdk_new_unencrypted(cPath.ptr, cCfg.ptr, out.ptr);
    check(ffi, code);
    return new Mdk(ffi, out.read());
  }

  /** Free the MDK handle. Must be called when done. */
  close() {
    if (this.#handle) {
      this.#ffi.sym.mdk_free(this.#handle);
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
    const cPk = this.#ffi.toCString(pubkey);
    const cRelays = this.#ffi.toCString(JSON.stringify(relays));
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_create_key_package, this.#handle, cPk.ptr, cRelays.ptr);
  }

  /**
   * Create a key package with options.
   * @param {string} pubkey
   * @param {string[]} relays
   * @param {boolean} protected_ — add NIP-70 protected tag
   */
  createKeyPackageWithOptions(pubkey, relays, protected_) {
    const cPk = this.#ffi.toCString(pubkey);
    const cRelays = this.#ffi.toCString(JSON.stringify(relays));
    return callWithJsonOut(
      this.#ffi,
      this.#ffi.sym.mdk_create_key_package_with_options,
      this.#handle, cPk.ptr, cRelays.ptr, protected_,
    );
  }

  /**
   * Parse and validate a key package from a Nostr event.
   * @param {object} event — Nostr event object
   * @returns {string}
   */
  parseKeyPackage(event) {
    const cEv = this.#ffi.toCString(JSON.stringify(event));
    return callWithStringOut(this.#ffi, this.#ffi.sym.mdk_parse_key_package, this.#handle, cEv.ptr);
  }

  // -- Groups ---------------------------------------------------------------

  /** Get all groups. @returns {object[]} */
  getGroups() {
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_groups, this.#handle);
  }

  /**
   * Get a single group by MLS group ID.
   * @param {string} mlsGroupId — hex
   * @returns {object|null}
   */
  getGroup(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_group, this.#handle, cGid.ptr);
  }

  /**
   * Get members of a group.
   * @param {string} mlsGroupId
   * @returns {string[]} — hex public keys
   */
  getMembers(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_members, this.#handle, cGid.ptr);
  }

  /**
   * Get group IDs needing a self-update.
   * @param {number} thresholdSecs
   * @returns {string[]} — hex group IDs
   */
  groupsNeedingSelfUpdate(thresholdSecs) {
    return callWithJsonOut(
      this.#ffi,
      this.#ffi.sym.mdk_groups_needing_self_update,
      this.#handle, thresholdSecs,
    );
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
    const cPk = this.#ffi.toCString(creatorPk);
    const cKp = this.#ffi.toCString(JSON.stringify(keyPackageEvents.map((e) => JSON.stringify(e))));
    const cName = this.#ffi.toCString(name);
    const cDesc = this.#ffi.toCString(description);
    const cRelays = this.#ffi.toCString(JSON.stringify(relays));
    const cAdmins = this.#ffi.toCString(JSON.stringify(admins));
    return callWithJsonOut(
      this.#ffi,
      this.#ffi.sym.mdk_create_group,
      this.#handle, cPk.ptr, cKp.ptr, cName.ptr, cDesc.ptr, cRelays.ptr, cAdmins.ptr,
    );
  }

  /**
   * Add members to a group.
   * @param {string} mlsGroupId
   * @param {object[]} keyPackageEvents
   */
  addMembers(mlsGroupId, keyPackageEvents) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cKp = this.#ffi.toCString(JSON.stringify(keyPackageEvents.map((e) => JSON.stringify(e))));
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_add_members, this.#handle, cGid.ptr, cKp.ptr);
  }

  /**
   * Remove members from a group.
   * @param {string} mlsGroupId
   * @param {string[]} pubkeys — hex public keys
   */
  removeMembers(mlsGroupId, pubkeys) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cPks = this.#ffi.toCString(JSON.stringify(pubkeys));
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_remove_members, this.#handle, cGid.ptr, cPks.ptr);
  }

  /**
   * Update group data.
   * @param {string} mlsGroupId
   * @param {object} update — { name?, description?, image_hash?, relays?, admins? }
   */
  updateGroupData(mlsGroupId, update) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cUpd = this.#ffi.toCString(JSON.stringify(update));
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_update_group_data, this.#handle, cGid.ptr, cUpd.ptr);
  }

  /**
   * Perform a self-update (key rotation).
   * @param {string} mlsGroupId
   */
  selfUpdate(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_self_update, this.#handle, cGid.ptr);
  }

  /**
   * Leave a group.
   * @param {string} mlsGroupId
   */
  leaveGroup(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_leave_group, this.#handle, cGid.ptr);
  }

  /** Merge pending commit. @param {string} mlsGroupId */
  mergePendingCommit(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    check(this.#ffi, this.#ffi.sym.mdk_merge_pending_commit(this.#handle, cGid.ptr));
  }

  /** Clear pending commit. @param {string} mlsGroupId */
  clearPendingCommit(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    check(this.#ffi, this.#ffi.sym.mdk_clear_pending_commit(this.#handle, cGid.ptr));
  }

  /** Sync group metadata from MLS. @param {string} mlsGroupId */
  syncGroupMetadata(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    check(this.#ffi, this.#ffi.sym.mdk_sync_group_metadata(this.#handle, cGid.ptr));
  }

  /**
   * Get relays for a group.
   * @param {string} mlsGroupId
   * @returns {string[]}
   */
  getRelays(mlsGroupId) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_relays, this.#handle, cGid.ptr);
  }

  // -- Messages -------------------------------------------------------------

  /**
   * Create a message in a group.
   * @param {string} mlsGroupId
   * @param {string} senderPk — hex
   * @param {string} content
   * @param {number} kind — Nostr event kind
   * @param {string[][]|null} [tags] — e.g. [["p","hex..."],["e","hex..."]]
   */
  createMessage(mlsGroupId, senderPk, content, kind, tags = null) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cPk = this.#ffi.toCString(senderPk);
    const cContent = this.#ffi.toCString(content);
    const cTags = tags ? this.#ffi.toCString(JSON.stringify(tags)) : { ptr: this.#ffi.nullptr };
    return callWithJsonOut(
      this.#ffi,
      this.#ffi.sym.mdk_create_message,
      this.#handle, cGid.ptr, cPk.ptr, cContent.ptr, kind, cTags.ptr,
    );
  }

  /**
   * Process an incoming MLS message.
   * @param {object} event — Nostr event
   * @returns {{ type: string, message?, result?, mls_group_id?, reason? }}
   */
  processMessage(event) {
    const cEv = this.#ffi.toCString(JSON.stringify(event));
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_process_message, this.#handle, cEv.ptr);
  }

  /**
   * Get messages for a group.
   * @param {string} mlsGroupId
   * @param {{ limit?: number, offset?: number, sortOrder?: string }} [opts]
   * @returns {object[]}
   */
  getMessages(mlsGroupId, opts = {}) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cSort = opts.sortOrder ? this.#ffi.toCString(opts.sortOrder) : { ptr: this.#ffi.nullptr };
    return callWithJsonOut(
      this.#ffi,
      this.#ffi.sym.mdk_get_messages,
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
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cEid = this.#ffi.toCString(eventId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_message, this.#handle, cGid.ptr, cEid.ptr);
  }

  /**
   * Get the most recent message.
   * @param {string} mlsGroupId
   * @param {"created_at_first"|"processed_at_first"} sortOrder
   */
  getLastMessage(mlsGroupId, sortOrder) {
    const cGid = this.#ffi.toCString(mlsGroupId);
    const cSort = this.#ffi.toCString(sortOrder);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_last_message, this.#handle, cGid.ptr, cSort.ptr);
  }

  // -- Welcomes -------------------------------------------------------------

  /**
   * Get pending welcomes.
   * @param {{ limit?: number, offset?: number }} [opts]
   */
  getPendingWelcomes(opts = {}) {
    return callWithJsonOut(
      this.#ffi,
      this.#ffi.sym.mdk_get_pending_welcomes,
      this.#handle, opts.limit ?? 0, opts.offset ?? 0,
    );
  }

  /**
   * Get a welcome by event ID.
   * @param {string} eventId
   */
  getWelcome(eventId) {
    const cEid = this.#ffi.toCString(eventId);
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_get_welcome, this.#handle, cEid.ptr);
  }

  /**
   * Process a welcome message.
   * @param {string} wrapperEventId — hex event ID
   * @param {object} rumor — unsigned event object
   */
  processWelcome(wrapperEventId, rumor) {
    const cWid = this.#ffi.toCString(wrapperEventId);
    const cRumor = this.#ffi.toCString(JSON.stringify(rumor));
    return callWithJsonOut(this.#ffi, this.#ffi.sym.mdk_process_welcome, this.#handle, cWid.ptr, cRumor.ptr);
  }

  /**
   * Accept a welcome.
   * @param {object} welcome — welcome object (as from processWelcome/getWelcome)
   */
  acceptWelcome(welcome) {
    const cJson = this.#ffi.toCString(JSON.stringify(welcome));
    check(this.#ffi, this.#ffi.sym.mdk_accept_welcome(this.#handle, cJson.ptr));
  }

  /**
   * Decline a welcome.
   * @param {object} welcome
   */
  declineWelcome(welcome) {
    const cJson = this.#ffi.toCString(JSON.stringify(welcome));
    check(this.#ffi, this.#ffi.sym.mdk_decline_welcome(this.#handle, cJson.ptr));
  }
}

// ---------------------------------------------------------------------------
// Free functions (media)
// ---------------------------------------------------------------------------

/**
 * Prepare a group image for upload.
 * @param {object} ffi — BunFfi or DenoFfi
 * @param {Uint8Array} data — raw image bytes
 * @param {string} mime — e.g. "image/png"
 */
export function prepareGroupImage(ffi, data, mime) {
  const cMime = ffi.toCString(mime);
  return callWithJsonOut(
    ffi,
    ffi.sym.mdk_prepare_group_image,
    ffi.bufferPtr(data), data.length, cMime.ptr,
  );
}

/**
 * Decrypt a group image.
 * @param {object} ffi
 * @param {Uint8Array} data — encrypted data
 * @param {Uint8Array|null} expectedHash — 32-byte SHA-256 hash (null to skip)
 * @param {Uint8Array} key — 32-byte key
 * @param {Uint8Array} nonce — 12-byte nonce
 * @returns {Uint8Array}
 */
export function decryptGroupImage(ffi, data, expectedHash, key, nonce) {
  const out = ffi.allocOutBytes();

  const code = ffi.sym.mdk_decrypt_group_image(
    ffi.bufferPtr(data), data.length,
    expectedHash ? ffi.bufferPtr(expectedHash) : ffi.nullptr,
    expectedHash ? expectedHash.length : 0,
    ffi.bufferPtr(key), key.length,
    ffi.bufferPtr(nonce), nonce.length,
    out.ptrPtr, out.lenPtr,
  );
  check(ffi, code);
  return out.readAndFree();
}

/**
 * Derive an upload keypair from an image key.
 * @param {object} ffi
 * @param {Uint8Array} key — 32-byte key
 * @param {number} version
 * @returns {string} — hex-encoded secret key
 */
export function deriveUploadKeypair(ffi, key, version) {
  return callWithStringOut(
    ffi,
    ffi.sym.mdk_derive_upload_keypair,
    ffi.bufferPtr(key), key.length, version,
  );
}
