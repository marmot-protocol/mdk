///! Idiomatic Zig wrapper for the MDK C bindings.
///!
///! Provides a safe, ergonomic interface to mdk-core's MLS + Nostr
///! group messaging functionality.  All strings are Zig slices; memory
///! management is handled automatically via RAII-style owned types.
const std = @import("std");
const raw = @import("c.zig").c;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors returned by MDK operations.
pub const Error = error{
    /// Storage-layer error (SQLite, I/O, etc.).
    Storage,
    /// MDK core error (MLS, protocol, crypto).
    MdkCore,
    /// Invalid input from the caller.
    InvalidInput,
    /// A required pointer argument was null (should not happen through this wrapper).
    NullPointer,
    /// An unknown/unexpected error code was returned.
    Unknown,
};

fn mapError(code: raw.MdkError) Error {
    return switch (code) {
        raw.MDK_ERROR_STORAGE => Error.Storage,
        raw.MDK_ERROR_MDK => Error.MdkCore,
        raw.MDK_ERROR_INVALID_INPUT => Error.InvalidInput,
        raw.MDK_ERROR_NULL_POINTER => Error.NullPointer,
        else => Error.Unknown,
    };
}

fn check(code: raw.MdkError) Error!void {
    if (code != raw.MDK_ERROR_OK) return mapError(code);
}

/// Retrieve the detailed error message from the last failed MDK call.
///
/// Returns `null` if no error has been recorded on this thread (or if the
/// message has already been consumed).  The returned `CString` must be
/// allowed to go out of scope (its `deinit` frees the C memory).
pub fn lastErrorMessage() ?CString {
    const ptr = raw.mdk_last_error_message();
    if (ptr == null) return null;
    return CString{ .ptr = ptr };
}

// ── Owned C types ───────────────────────────────────────────────────────────

/// An owned, null-terminated C string allocated by the Rust side.
///
/// Call `deinit()` when done, or use `slice()` to read the contents.
pub const CString = struct {
    ptr: [*c]u8,

    /// View the string as a Zig slice (without the null terminator).
    pub fn slice(self: CString) []const u8 {
        return std.mem.sliceTo(self.ptr, 0);
    }

    /// Release the C-allocated memory.
    pub fn deinit(self: CString) void {
        raw.mdk_string_free(self.ptr);
    }
};

/// Owned byte array allocated by the Rust side.
///
/// Call `deinit()` when done, or use `slice()` to read the contents.
pub const CBytes = struct {
    ptr: [*c]u8,
    len: usize,

    /// View as a Zig slice.
    pub fn bytes(self: CBytes) []const u8 {
        return self.ptr[0..self.len];
    }

    /// Release the C-allocated memory.
    pub fn deinit(self: CBytes) void {
        raw.mdk_bytes_free(self.ptr, self.len);
    }
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a Zig slice to a null-terminated C pointer.
///
/// Uses `allocator` to create a temporary copy with a sentinel.
/// Caller must free the returned pointer.
///
/// NOTE: For performance-critical paths with many string arguments, consider
/// using sentinel-terminated slices (`[:0]const u8`) and calling the raw
/// C functions in the `c` module directly to avoid the allocation overhead.
fn sliceToC(allocator: std.mem.Allocator, s: []const u8) std.mem.Allocator.Error![*c]const u8 {
    const buf = try allocator.alloc(u8, s.len + 1);
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return @ptrCast(buf.ptr);
}

fn freeCStr(allocator: std.mem.Allocator, p: [*c]const u8, len: usize) void {
    const ptr: [*]u8 = @ptrCast(@constCast(p));
    allocator.free(ptr[0 .. len + 1]);
}

/// Optional Zig slice → nullable C string pointer.
fn optSliceToC(allocator: std.mem.Allocator, s: ?[]const u8) std.mem.Allocator.Error![*c]const u8 {
    if (s) |val| return sliceToC(allocator, val);
    return null;
}

fn freeOptCStr(allocator: std.mem.Allocator, p: [*c]const u8, s: ?[]const u8) void {
    if (s) |val| freeCStr(allocator, p, val.len);
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Optional configuration for MDK behaviour.  Mirrors the JSON config
/// accepted by the C constructors.  All fields default to `null` (use
/// library defaults).
pub const Config = struct {
    max_event_age_secs: ?u64 = null,
    max_future_skew_secs: ?u64 = null,
    out_of_order_tolerance: ?u32 = null,
    maximum_forward_distance: ?u32 = null,
    epoch_snapshot_retention: ?u32 = null,
    snapshot_ttl_seconds: ?u64 = null,
};

fn configToJson(allocator: std.mem.Allocator, cfg: ?Config) std.mem.Allocator.Error!?[]const u8 {
    const conf = cfg orelse return null;
    const result = try std.json.Stringify.valueAlloc(allocator, conf, .{ .emit_null_optional_fields = false });
    return result;
}

// ── Sort order ──────────────────────────────────────────────────────────────

/// Sort order for message queries.
pub const SortOrder = enum {
    created_at_first,
    processed_at_first,

    fn asSlice(self: SortOrder) []const u8 {
        return switch (self) {
            .created_at_first => "created_at_first",
            .processed_at_first => "processed_at_first",
        };
    }
};

// ── Mdk handle ──────────────────────────────────────────────────────────────

/// An MDK instance wrapping the opaque C handle.
///
/// Create with `init`, `initWithKey`, or `initUnencrypted`.
/// Call `deinit()` when done — this frees all internal state.
pub const Mdk = struct {
    handle: *raw.MdkHandle,
    allocator: std.mem.Allocator,

    // ── Constructors ────────────────────────────────────────────────────

    /// Create a new MDK instance with encrypted storage using the platform
    /// keyring for key management.
    pub fn init(
        allocator: std.mem.Allocator,
        db_path: []const u8,
        service_id: []const u8,
        db_key_id: []const u8,
        config: ?Config,
    ) (Error || std.mem.Allocator.Error)!Mdk {
        const c_path = try sliceToC(allocator, db_path);
        defer freeCStr(allocator, c_path, db_path.len);
        const c_svc = try sliceToC(allocator, service_id);
        defer freeCStr(allocator, c_svc, service_id.len);
        const c_key = try sliceToC(allocator, db_key_id);
        defer freeCStr(allocator, c_key, db_key_id.len);

        const cfg_json = try configToJson(allocator, config);
        defer if (cfg_json) |j| allocator.free(j);
        const c_cfg = if (cfg_json) |j| try sliceToC(allocator, j) else null;
        defer if (cfg_json) |j| freeCStr(allocator, c_cfg.?, j.len);

        var out: ?*raw.MdkHandle = null;
        try check(raw.mdk_new(c_path, c_svc, c_key, c_cfg, &out));
        return .{ .handle = out.?, .allocator = allocator };
    }

    /// Create a new MDK instance with encrypted storage using a directly
    /// provided 32-byte key.
    pub fn initWithKey(
        allocator: std.mem.Allocator,
        db_path: []const u8,
        encryption_key: []const u8,
        config: ?Config,
    ) (Error || std.mem.Allocator.Error)!Mdk {
        const c_path = try sliceToC(allocator, db_path);
        defer freeCStr(allocator, c_path, db_path.len);

        const cfg_json = try configToJson(allocator, config);
        defer if (cfg_json) |j| allocator.free(j);
        const c_cfg = if (cfg_json) |j| try sliceToC(allocator, j) else null;
        defer if (cfg_json) |j| freeCStr(allocator, c_cfg.?, j.len);

        var out: ?*raw.MdkHandle = null;
        try check(raw.mdk_new_with_key(
            c_path,
            encryption_key.ptr,
            encryption_key.len,
            c_cfg,
            &out,
        ));
        return .{ .handle = out.?, .allocator = allocator };
    }

    /// Create a new MDK instance with **unencrypted** storage.
    ///
    /// WARNING: Sensitive MLS state will be stored in plaintext.
    /// Only use for development or testing.
    pub fn initUnencrypted(
        allocator: std.mem.Allocator,
        db_path: []const u8,
        config: ?Config,
    ) (Error || std.mem.Allocator.Error)!Mdk {
        const c_path = try sliceToC(allocator, db_path);
        defer freeCStr(allocator, c_path, db_path.len);

        const cfg_json = try configToJson(allocator, config);
        defer if (cfg_json) |j| allocator.free(j);
        const c_cfg = if (cfg_json) |j| try sliceToC(allocator, j) else null;
        defer if (cfg_json) |j| freeCStr(allocator, c_cfg.?, j.len);

        var out: ?*raw.MdkHandle = null;
        try check(raw.mdk_new_unencrypted(c_path, c_cfg, &out));
        return .{ .handle = out.?, .allocator = allocator };
    }

    /// Free the MDK handle and all associated resources.
    pub fn deinit(self: *Mdk) void {
        raw.mdk_free(self.handle);
        self.handle = undefined;
    }

    // ── Key Packages ────────────────────────────────────────────────────

    /// Create a key package for a Nostr event (no NIP-70 protected tag).
    pub fn createKeyPackage(
        self: *const Mdk,
        pubkey: []const u8,
        relays_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_pk = try sliceToC(self.allocator, pubkey);
        defer freeCStr(self.allocator, c_pk, pubkey.len);
        const c_relays = try sliceToC(self.allocator, relays_json);
        defer freeCStr(self.allocator, c_relays, relays_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_create_key_package(self.handle, c_pk, c_relays, &out));
        return CString{ .ptr = out };
    }

    /// Create a key package with the option to add the NIP-70 protected tag.
    pub fn createKeyPackageWithOptions(
        self: *const Mdk,
        pubkey: []const u8,
        relays_json: []const u8,
        protected: bool,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_pk = try sliceToC(self.allocator, pubkey);
        defer freeCStr(self.allocator, c_pk, pubkey.len);
        const c_relays = try sliceToC(self.allocator, relays_json);
        defer freeCStr(self.allocator, c_relays, relays_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_create_key_package_with_options(self.handle, c_pk, c_relays, protected, &out));
        return CString{ .ptr = out };
    }

    /// Parse and validate a key package from a Nostr event JSON.
    pub fn parseKeyPackage(
        self: *const Mdk,
        event_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_ev = try sliceToC(self.allocator, event_json);
        defer freeCStr(self.allocator, c_ev, event_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_parse_key_package(self.handle, c_ev, &out));
        return CString{ .ptr = out };
    }

    // ── Groups ──────────────────────────────────────────────────────────

    /// Get all groups as a JSON array.
    pub fn getGroups(self: *const Mdk) Error!CString {
        var out: [*c]u8 = null;
        try check(raw.mdk_get_groups(self.handle, &out));
        return CString{ .ptr = out };
    }

    /// Get a single group by hex-encoded MLS group ID.
    pub fn getGroup(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_group(self.handle, c_gid, &out));
        return CString{ .ptr = out };
    }

    /// Get members of a group as a JSON array of hex public keys.
    pub fn getMembers(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_members(self.handle, c_gid, &out));
        return CString{ .ptr = out };
    }

    /// Get group IDs needing a self-update as a JSON array of hex strings.
    pub fn groupsNeedingSelfUpdate(
        self: *const Mdk,
        threshold_secs: u64,
    ) Error!CString {
        var out: [*c]u8 = null;
        try check(raw.mdk_groups_needing_self_update(self.handle, threshold_secs, &out));
        return CString{ .ptr = out };
    }

    /// Create a new group.
    pub fn createGroup(
        self: *const Mdk,
        creator_pk: []const u8,
        key_packages_json: []const u8,
        name: []const u8,
        description: []const u8,
        relays_json: []const u8,
        admins_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_pk = try sliceToC(self.allocator, creator_pk);
        defer freeCStr(self.allocator, c_pk, creator_pk.len);
        const c_kp = try sliceToC(self.allocator, key_packages_json);
        defer freeCStr(self.allocator, c_kp, key_packages_json.len);
        const c_name = try sliceToC(self.allocator, name);
        defer freeCStr(self.allocator, c_name, name.len);
        const c_desc = try sliceToC(self.allocator, description);
        defer freeCStr(self.allocator, c_desc, description.len);
        const c_relays = try sliceToC(self.allocator, relays_json);
        defer freeCStr(self.allocator, c_relays, relays_json.len);
        const c_admins = try sliceToC(self.allocator, admins_json);
        defer freeCStr(self.allocator, c_admins, admins_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_create_group(self.handle, c_pk, c_kp, c_name, c_desc, c_relays, c_admins, &out));
        return CString{ .ptr = out };
    }

    /// Add members to a group.
    pub fn addMembers(
        self: *const Mdk,
        mls_group_id: []const u8,
        key_packages_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        const c_kp = try sliceToC(self.allocator, key_packages_json);
        defer freeCStr(self.allocator, c_kp, key_packages_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_add_members(self.handle, c_gid, c_kp, &out));
        return CString{ .ptr = out };
    }

    /// Remove members from a group.
    pub fn removeMembers(
        self: *const Mdk,
        mls_group_id: []const u8,
        pubkeys_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        const c_pks = try sliceToC(self.allocator, pubkeys_json);
        defer freeCStr(self.allocator, c_pks, pubkeys_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_remove_members(self.handle, c_gid, c_pks, &out));
        return CString{ .ptr = out };
    }

    /// Update group data (name, description, image, relays, admins).
    pub fn updateGroupData(
        self: *const Mdk,
        mls_group_id: []const u8,
        update_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        const c_upd = try sliceToC(self.allocator, update_json);
        defer freeCStr(self.allocator, c_upd, update_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_update_group_data(self.handle, c_gid, c_upd, &out));
        return CString{ .ptr = out };
    }

    /// Perform a self-update (key rotation) for a group.
    pub fn selfUpdate(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_self_update(self.handle, c_gid, &out));
        return CString{ .ptr = out };
    }

    /// Create a proposal to leave the group.
    pub fn leaveGroup(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_leave_group(self.handle, c_gid, &out));
        return CString{ .ptr = out };
    }

    /// Merge pending commit for a group.
    pub fn mergePendingCommit(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!void {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        try check(raw.mdk_merge_pending_commit(self.handle, c_gid));
    }

    /// Clear pending commit for a group (rollback).
    pub fn clearPendingCommit(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!void {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        try check(raw.mdk_clear_pending_commit(self.handle, c_gid));
    }

    /// Sync group metadata from MLS state.
    pub fn syncGroupMetadata(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!void {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        try check(raw.mdk_sync_group_metadata(self.handle, c_gid));
    }

    /// Get relays for a group as a JSON array of URL strings.
    pub fn getRelays(
        self: *const Mdk,
        mls_group_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_relays(self.handle, c_gid, &out));
        return CString{ .ptr = out };
    }

    // ── Messages ────────────────────────────────────────────────────────

    /// Create a message in a group.
    pub fn createMessage(
        self: *const Mdk,
        mls_group_id: []const u8,
        sender_pk: []const u8,
        content: []const u8,
        kind: u16,
        tags_json: ?[]const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        const c_pk = try sliceToC(self.allocator, sender_pk);
        defer freeCStr(self.allocator, c_pk, sender_pk.len);
        const c_content = try sliceToC(self.allocator, content);
        defer freeCStr(self.allocator, c_content, content.len);

        const c_tags = try optSliceToC(self.allocator, tags_json);
        defer freeOptCStr(self.allocator, c_tags, tags_json);

        var out: [*c]u8 = null;
        try check(raw.mdk_create_message(self.handle, c_gid, c_pk, c_content, kind, c_tags, &out));
        return CString{ .ptr = out };
    }

    /// Process an incoming MLS message.
    pub fn processMessage(
        self: *const Mdk,
        event_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_ev = try sliceToC(self.allocator, event_json);
        defer freeCStr(self.allocator, c_ev, event_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_process_message(self.handle, c_ev, &out));
        return CString{ .ptr = out };
    }

    /// Get messages for a group with optional pagination.
    ///
    /// Pass `0` for limit/offset to use defaults.
    pub fn getMessages(
        self: *const Mdk,
        mls_group_id: []const u8,
        limit: u32,
        offset: u32,
        sort_order: ?SortOrder,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);

        const c_sort = if (sort_order) |so| try sliceToC(self.allocator, so.asSlice()) else null;
        defer if (sort_order) |so| freeCStr(self.allocator, c_sort.?, so.asSlice().len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_messages(self.handle, c_gid, limit, offset, c_sort, &out));
        return CString{ .ptr = out };
    }

    /// Get a single message by event ID within a group.
    pub fn getMessage(
        self: *const Mdk,
        mls_group_id: []const u8,
        event_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        const c_eid = try sliceToC(self.allocator, event_id);
        defer freeCStr(self.allocator, c_eid, event_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_message(self.handle, c_gid, c_eid, &out));
        return CString{ .ptr = out };
    }

    /// Get the most recent message in a group under the given sort order.
    pub fn getLastMessage(
        self: *const Mdk,
        mls_group_id: []const u8,
        sort_order: SortOrder,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_gid = try sliceToC(self.allocator, mls_group_id);
        defer freeCStr(self.allocator, c_gid, mls_group_id.len);
        const c_sort = try sliceToC(self.allocator, sort_order.asSlice());
        defer freeCStr(self.allocator, c_sort, sort_order.asSlice().len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_last_message(self.handle, c_gid, c_sort, &out));
        return CString{ .ptr = out };
    }

    // ── Welcomes ────────────────────────────────────────────────────────

    /// Get pending welcomes with optional pagination.
    ///
    /// Pass `0` for limit/offset to use defaults.
    pub fn getPendingWelcomes(
        self: *const Mdk,
        limit: u32,
        offset: u32,
    ) Error!CString {
        var out: [*c]u8 = null;
        try check(raw.mdk_get_pending_welcomes(self.handle, limit, offset, &out));
        return CString{ .ptr = out };
    }

    /// Get a welcome by hex-encoded event ID.
    pub fn getWelcome(
        self: *const Mdk,
        event_id: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_eid = try sliceToC(self.allocator, event_id);
        defer freeCStr(self.allocator, c_eid, event_id.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_get_welcome(self.handle, c_eid, &out));
        return CString{ .ptr = out };
    }

    /// Process a welcome message.
    pub fn processWelcome(
        self: *const Mdk,
        wrapper_event_id: []const u8,
        rumor_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!CString {
        const c_wid = try sliceToC(self.allocator, wrapper_event_id);
        defer freeCStr(self.allocator, c_wid, wrapper_event_id.len);
        const c_rumor = try sliceToC(self.allocator, rumor_json);
        defer freeCStr(self.allocator, c_rumor, rumor_json.len);

        var out: [*c]u8 = null;
        try check(raw.mdk_process_welcome(self.handle, c_wid, c_rumor, &out));
        return CString{ .ptr = out };
    }

    /// Accept a welcome message (pass the JSON as returned by processWelcome/getWelcome).
    pub fn acceptWelcome(
        self: *const Mdk,
        welcome_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!void {
        const c_json = try sliceToC(self.allocator, welcome_json);
        defer freeCStr(self.allocator, c_json, welcome_json.len);
        try check(raw.mdk_accept_welcome(self.handle, c_json));
    }

    /// Decline a welcome message.
    pub fn declineWelcome(
        self: *const Mdk,
        welcome_json: []const u8,
    ) (Error || std.mem.Allocator.Error)!void {
        const c_json = try sliceToC(self.allocator, welcome_json);
        defer freeCStr(self.allocator, c_json, welcome_json.len);
        try check(raw.mdk_decline_welcome(self.handle, c_json));
    }
};

// ── Free functions (media) ──────────────────────────────────────────────────

/// Prepare a group image for upload to Blossom.
///
/// Returns a JSON string with encrypted data, keys, and metadata.
pub fn prepareGroupImage(
    allocator: std.mem.Allocator,
    data: []const u8,
    mime: []const u8,
) (Error || std.mem.Allocator.Error)!CString {
    const c_mime = try sliceToC(allocator, mime);
    defer freeCStr(allocator, c_mime, mime.len);

    var out: [*c]u8 = null;
    try check(raw.mdk_prepare_group_image(data.ptr, data.len, c_mime, &out));
    return CString{ .ptr = out };
}

/// Decrypt a group image.
///
/// Returns the decrypted image bytes as a `CBytes` (call `deinit()` when done).
pub fn decryptGroupImage(
    data: []const u8,
    expected_hash: ?*const [32]u8,
    key: *const [32]u8,
    nonce: *const [12]u8,
) Error!CBytes {
    var out_ptr: [*c]u8 = null;
    var out_len: usize = 0;

    const hash_ptr: [*c]const u8 = if (expected_hash) |h| h else null;
    const hash_len: usize = if (expected_hash != null) 32 else 0;

    try check(raw.mdk_decrypt_group_image(
        data.ptr,
        data.len,
        hash_ptr,
        hash_len,
        key,
        32,
        nonce,
        12,
        &out_ptr,
        &out_len,
    ));
    return CBytes{ .ptr = out_ptr, .len = out_len };
}

/// Derive an upload keypair from an image key.
///
/// Returns the hex-encoded secret key.
pub fn deriveUploadKeypair(
    key: *const [32]u8,
    version: u16,
) Error!CString {
    var out: [*c]u8 = null;
    try check(raw.mdk_derive_upload_keypair(key, 32, version, &out));
    return CString{ .ptr = out };
}

// ── Re-exports ──────────────────────────────────────────────────────────────

/// Access the raw C bindings directly if needed.
pub const c = raw;

// ── Tests ───────────────────────────────────────────────────────────────────

test "CString slice and deinit" {
    // Smoke test: lastErrorMessage should be null when no error has occurred.
    const msg = lastErrorMessage();
    try std.testing.expect(msg == null);
}

test "Error mapping" {
    try std.testing.expectEqual(Error.Storage, mapError(raw.MDK_ERROR_STORAGE));
    try std.testing.expectEqual(Error.MdkCore, mapError(raw.MDK_ERROR_MDK));
    try std.testing.expectEqual(Error.InvalidInput, mapError(raw.MDK_ERROR_INVALID_INPUT));
    try std.testing.expectEqual(Error.NullPointer, mapError(raw.MDK_ERROR_NULL_POINTER));
}

test "check passes on OK" {
    try check(raw.MDK_ERROR_OK);
}

test "check returns error on non-OK" {
    const result = check(raw.MDK_ERROR_STORAGE);
    try std.testing.expectEqual(Error.Storage, result);
}

test "SortOrder asSlice" {
    try std.testing.expectEqualStrings("created_at_first", SortOrder.created_at_first.asSlice());
    try std.testing.expectEqualStrings("processed_at_first", SortOrder.processed_at_first.asSlice());
}

test "sliceToC and freeCStr round-trip" {
    const allocator = std.testing.allocator;
    const input = "hello world";
    const c_ptr = try sliceToC(allocator, input);
    defer freeCStr(allocator, c_ptr, input.len);

    // The C string should be null-terminated
    const slice = std.mem.sliceTo(c_ptr, 0);
    try std.testing.expectEqualStrings(input, slice);
}

test "sliceToC empty string" {
    const allocator = std.testing.allocator;
    const input = "";
    const c_ptr = try sliceToC(allocator, input);
    defer freeCStr(allocator, c_ptr, input.len);

    const slice = std.mem.sliceTo(c_ptr, 0);
    try std.testing.expectEqualStrings("", slice);
}

test "optSliceToC with null" {
    const allocator = std.testing.allocator;
    const result = try optSliceToC(allocator, null);
    try std.testing.expect(result == null);
}

test "optSliceToC with value" {
    const allocator = std.testing.allocator;
    const input: ?[]const u8 = "test";
    const c_ptr = try optSliceToC(allocator, input);
    defer freeOptCStr(allocator, c_ptr, input);

    const slice = std.mem.sliceTo(c_ptr, 0);
    try std.testing.expectEqualStrings("test", slice);
}

test "configToJson with null config" {
    const allocator = std.testing.allocator;
    const result = try configToJson(allocator, null);
    try std.testing.expect(result == null);
}

test "configToJson with defaults" {
    const allocator = std.testing.allocator;
    const cfg = Config{};
    const result = try configToJson(allocator, cfg);
    // All fields are null, so this should be an empty object or have no fields
    try std.testing.expect(result != null);
    defer allocator.free(result.?);
}

test "configToJson with some values" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .max_event_age_secs = 86400,
        .out_of_order_tolerance = 50,
    };
    const result = try configToJson(allocator, cfg);
    try std.testing.expect(result != null);
    defer allocator.free(result.?);
    // Parse it back to verify it's valid JSON
    const parsed = try std.json.parseFromSlice(Config, allocator, result.?, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?u64, 86400), parsed.value.max_event_age_secs);
    try std.testing.expectEqual(@as(?u32, 50), parsed.value.out_of_order_tolerance);
    try std.testing.expect(parsed.value.max_future_skew_secs == null);
}
