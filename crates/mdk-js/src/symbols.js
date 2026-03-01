/**
 * FFI symbol definitions for libmdk.
 *
 * Runtime-agnostic: each backend (Bun/Deno) transforms these into
 * the format its dlopen expects.
 *
 * Type shorthand:
 *   "ptr"    — opaque pointer (void*, char*, struct*)
 *   "cstr"   — const char* input
 *   "u8"     — uint8_t
 *   "u16"    — uint16_t
 *   "u32"    — uint32_t
 *   "u64"    — uint64_t
 *   "usize"  — uintptr_t / size_t
 *   "bool"   — C bool
 *   "i32"    — int32_t (used for MdkError enum)
 *   "void"   — void
 */

/** @type {Record<string, { params: string[], result: string }>} */
export const symbols = {
  // -- Lifecycle --
  mdk_new: {
    params: ["ptr", "ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_new_with_key: {
    params: ["ptr", "ptr", "usize", "ptr", "ptr"],
    result: "i32",
  },
  mdk_new_unencrypted: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_free: {
    params: ["ptr"],
    result: "void",
  },

  // -- Error --
  mdk_last_error_message: {
    params: [],
    result: "ptr",
  },

  // -- Memory --
  mdk_string_free: {
    params: ["ptr"],
    result: "void",
  },
  mdk_bytes_free: {
    params: ["ptr", "usize"],
    result: "void",
  },

  // -- Key packages --
  mdk_create_key_package: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_create_key_package_with_options: {
    params: ["ptr", "ptr", "ptr", "bool", "ptr"],
    result: "i32",
  },
  mdk_parse_key_package: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },

  // -- Groups --
  mdk_get_groups: {
    params: ["ptr", "ptr"],
    result: "i32",
  },
  mdk_get_group: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_get_members: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_groups_needing_self_update: {
    params: ["ptr", "u64", "ptr"],
    result: "i32",
  },
  mdk_create_group: {
    params: ["ptr", "ptr", "ptr", "ptr", "ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_add_members: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_remove_members: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_update_group_data: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_self_update: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_leave_group: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_merge_pending_commit: {
    params: ["ptr", "ptr"],
    result: "i32",
  },
  mdk_clear_pending_commit: {
    params: ["ptr", "ptr"],
    result: "i32",
  },
  mdk_sync_group_metadata: {
    params: ["ptr", "ptr"],
    result: "i32",
  },
  mdk_get_relays: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },

  // -- Messages --
  mdk_create_message: {
    params: ["ptr", "ptr", "ptr", "ptr", "u16", "ptr", "ptr"],
    result: "i32",
  },
  mdk_process_message: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_get_messages: {
    params: ["ptr", "ptr", "u32", "u32", "ptr", "ptr"],
    result: "i32",
  },
  mdk_get_message: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_get_last_message: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },

  // -- Welcomes --
  mdk_get_pending_welcomes: {
    params: ["ptr", "u32", "u32", "ptr"],
    result: "i32",
  },
  mdk_get_welcome: {
    params: ["ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_process_welcome: {
    params: ["ptr", "ptr", "ptr", "ptr"],
    result: "i32",
  },
  mdk_accept_welcome: {
    params: ["ptr", "ptr"],
    result: "i32",
  },
  mdk_decline_welcome: {
    params: ["ptr", "ptr"],
    result: "i32",
  },

  // -- Media (free functions) --
  mdk_prepare_group_image: {
    params: ["ptr", "usize", "ptr", "ptr"],
    result: "i32",
  },
  mdk_decrypt_group_image: {
    params: ["ptr", "usize", "ptr", "usize", "ptr", "usize", "ptr", "usize", "ptr", "ptr"],
    result: "i32",
  },
  mdk_derive_upload_keypair: {
    params: ["ptr", "usize", "u16", "ptr"],
    result: "i32",
  },
};
