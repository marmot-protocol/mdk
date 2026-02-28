# MDK Zig Bindings

Idiomatic Zig wrapper for the [Marmot Development Kit](https://github.com/marmot-protocol/mdk) — decentralized, encrypted group messaging for Zig applications.

## What is MDK?

MDK combines [MLS (Messaging Layer Security)](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr](https://github.com/nostr-protocol/nostr) for real end-to-end encrypted group messaging. Forward secrecy, post-compromise security, automatic key rotation, metadata protection. No server required.

This package provides a safe Zig API over the [C bindings](https://github.com/marmot-protocol/mdk-cbindings), handling null-termination, memory management, and error translation automatically.

## Installation

### As a Zig Package Dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .mdk = .{
        .url = "https://github.com/marmot-protocol/mdk-zig/archive/refs/tags/v0.6.0.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const mdk_dep = b.dependency("mdk", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("mdk", mdk_dep.module("mdk"));
```

### Prebuilt Native Libraries

The package ships prebuilt `libmdk` for each platform in `lib/`. If you're building from source instead, build the Rust C bindings first:

```bash
git clone https://github.com/marmot-protocol/mdk.git
cd mdk
cargo build --release -p mdk-cbindings
```

## Quick Start

```zig
const mdk = @import("mdk");
const std = @import("std");

pub fn main() !void {
    var allocator = std.heap.page_allocator;

    // Create an unencrypted instance (dev/testing only!)
    var m = try mdk.Mdk.initUnencrypted(allocator, "/tmp/mdk-test.db", null);
    defer m.deinit();

    // Get all groups
    const groups = try m.getGroups();
    defer groups.deinit();
    std.debug.print("Groups: {s}\n", .{groups.slice()});
}
```

## API Overview

### Mdk Instance

```zig
// Encrypted storage with platform keyring
var m = try mdk.Mdk.init(allocator, db_path, service_id, db_key_id, null);

// Encrypted storage with a provided key
var m = try mdk.Mdk.initWithKey(allocator, db_path, &key_bytes, null);

// Unencrypted (dev only)
var m = try mdk.Mdk.initUnencrypted(allocator, db_path, null);

// Always call deinit when done
defer m.deinit();
```

The optional last parameter accepts a `mdk.Config` struct for tuning:

```zig
var m = try mdk.Mdk.initUnencrypted(allocator, "/tmp/test.db", .{
    .max_event_age_secs = 86400,
});
```

### Owned Return Types

Functions that return data from Rust use owned types that must be freed:

- **`CString`** — an owned null-terminated string. Call `.slice()` to read, `.deinit()` to free.
- **`CBytes`** — an owned byte array. Call `.bytes()` to read, `.deinit()` to free.

```zig
const groups = try m.getGroups();
defer groups.deinit();

const json = groups.slice(); // []const u8
```

### Error Handling

All methods return a Zig error set: `Storage`, `MdkCore`, `InvalidInput`, `NullPointer`, `Unknown`.

For detailed error messages after a failure:

```zig
const result = m.getGroup(group_id) catch |err| {
    if (mdk.lastErrorMessage()) |msg| {
        defer msg.deinit();
        std.debug.print("Error: {s}\n", .{msg.slice()});
    }
    return err;
};
```

### Key Packages

```zig
const kp = try m.createKeyPackage(pubkey_hex, relays_json);
defer kp.deinit();
// kp.slice() is a JSON object with key_package, tags, hash_ref

const parsed = try m.parseKeyPackage(event_json);
defer parsed.deinit();
```

### Groups

```zig
const groups = try m.getGroups();                    // JSON array
const group = try m.getGroup(mls_group_id);          // JSON or "null"
const members = try m.getMembers(mls_group_id);      // JSON array of hex pubkeys
const relays = try m.getRelays(mls_group_id);        // JSON array of URLs

const result = try m.createGroup(creator_pk, kp_json, name, desc, relays_json, admins_json);
const result = try m.addMembers(mls_group_id, kp_json);
const result = try m.removeMembers(mls_group_id, pubkeys_json);
const result = try m.updateGroupData(mls_group_id, update_json);
const result = try m.selfUpdate(mls_group_id);
const result = try m.leaveGroup(mls_group_id);

try m.mergePendingCommit(mls_group_id);
try m.clearPendingCommit(mls_group_id);
try m.syncGroupMetadata(mls_group_id);
```

### Messages

```zig
const event = try m.createMessage(mls_group_id, sender_pk, "Hello!", 9, null);
defer event.deinit();

const result = try m.processMessage(event_json);
defer result.deinit();

const msgs = try m.getMessages(mls_group_id, 100, 0, .created_at_first);
defer msgs.deinit();

const msg = try m.getMessage(mls_group_id, event_id);
defer msg.deinit();

const last = try m.getLastMessage(mls_group_id, .created_at_first);
defer last.deinit();
```

### Welcomes

```zig
const welcomes = try m.getPendingWelcomes(0, 0);
defer welcomes.deinit();

const w = try m.getWelcome(event_id);
defer w.deinit();

const processed = try m.processWelcome(wrapper_event_id, rumor_json);
defer processed.deinit();

try m.acceptWelcome(welcome_json);
try m.declineWelcome(welcome_json);
```

### Media (Free Functions)

```zig
const prepared = try mdk.prepareGroupImage(allocator, image_bytes, "image/png");
defer prepared.deinit();

const decrypted = try mdk.decryptGroupImage(encrypted, &hash, &key, &nonce);
defer decrypted.deinit();

const secret_key = try mdk.deriveUploadKeypair(&image_key, 2);
defer secret_key.deinit();
```

## Data Format

All complex types (groups, messages, welcomes) are returned as JSON strings via `CString`. Parse them with `std.json` or your preferred JSON library. The raw C bindings are also available via `mdk.c` if you need direct access.

## Build & Test

```bash
# Build the Rust C library first
cargo build -p mdk-cbindings

# Build the Zig module
cd crates/mdk-zig
zig build

# Run tests
zig build test
```

## Further Reading

- [Marmot Protocol Spec](https://github.com/marmot-protocol/marmot)
- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [Nostr Protocol](https://github.com/nostr-protocol/nostr)
- [C Bindings](https://github.com/marmot-protocol/mdk-cbindings) (the layer this wraps)
