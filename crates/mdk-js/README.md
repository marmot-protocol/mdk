# MDK JavaScript Bindings

JavaScript bindings for the [Marmot Development Kit](https://github.com/marmot-protocol/mdk) — decentralized, encrypted group messaging for **Bun** and **Deno**.

## What is MDK?

MDK combines [MLS (Messaging Layer Security)](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr](https://github.com/nostr-protocol/nostr) for real end-to-end encrypted group messaging. Forward secrecy, post-compromise security, automatic key rotation, metadata protection. No server required.

These bindings use native FFI (`bun:ffi` / `Deno.dlopen`) to call the [C bindings](https://github.com/marmot-protocol/mdk-cbindings) directly — no WASM, no N-API, no overhead. Note: the linked repos (`mdk-cbindings`, `mdk-js`) are auto-populated by CI on first publish.

## Installation

Clone or download from [mdk-js releases](https://github.com/marmot-protocol/mdk-js/releases). The package ships with prebuilt native libraries for Linux, macOS, and Windows.

```text
src/          # JS source
native/       # prebuilt libmdk per platform
  linux-x86_64/libmdk.so
  macos-aarch64/libmdk.dylib
  windows-x86_64/mdk.dll
```

### Build from Source

If you prefer building the native library yourself:

```bash
git clone https://github.com/marmot-protocol/mdk.git
cd mdk
cargo build --release -p mdk-cbindings
```

## Quick Start

### Bun

```js
import { Mdk } from "./src/index.js";

const mdk = Mdk.createUnencrypted("/tmp/mdk-test.db");

const groups = mdk.getGroups();
console.log("Groups:", groups);

mdk.close();
```

### Deno

```ts
import { Mdk } from "./src/mod.ts";

const mdk = Mdk.createUnencrypted("/tmp/mdk-test.db");

const groups = mdk.getGroups();
console.log("Groups:", groups);

mdk.close();
```

Deno requires the `--allow-ffi` flag:

```bash
deno run --allow-ffi your_script.ts
```

## API Overview

### Creating an MDK Instance

```js
// Encrypted storage with platform keyring
const mdk = Mdk.create("/path/to/mdk.db", "com.example.myapp", "mdk.db.key");

// Encrypted storage with a provided 32-byte key
const mdk = Mdk.createWithKey("/path/to/mdk.db", key);

// Unencrypted (dev/testing only!)
const mdk = Mdk.createUnencrypted("/path/to/mdk.db");

// Optional config
const mdk = Mdk.createUnencrypted("/path/to/mdk.db", {
  max_event_age_secs: 86400,
});

// Always close when done
mdk.close();
```

The native library is loaded automatically — no manual `dlopen` or path configuration needed.

### Error Handling

All methods throw `MdkError` on failure with a `.code` property and a detailed message:

```js
import { Mdk, MdkError, ErrorCode } from "./src/index.js";

try {
  const group = mdk.getGroup("deadbeef...");
} catch (e) {
  if (e instanceof MdkError) {
    console.error(`MDK error (code ${e.code}): ${e.message}`);
  }
}
```

Error codes: `ErrorCode.OK`, `ErrorCode.STORAGE`, `ErrorCode.MDK`, `ErrorCode.INVALID_INPUT`, `ErrorCode.NULL_POINTER`.

### Key Packages

```js
// Create a key package for publishing as a Nostr kind 443 event
const result = mdk.createKeyPackage(myPubkeyHex, ["wss://relay.example.com"]);
// result = { key_package: "hex...", tags: [["p", "..."], ...], hash_ref: [...] }

// With NIP-70 protected tag
const result = mdk.createKeyPackageWithOptions(myPubkeyHex, relays, true);

// Parse a key package from a received Nostr event
const content = mdk.parseKeyPackage(eventObject);
```

### Groups

```js
// Create a group
const result = mdk.createGroup(
  creatorPubkeyHex,
  [keyPackageEvent1, keyPackageEvent2],  // Nostr event objects
  "My Group",
  "A secure group chat",
  ["wss://relay.example.com"],
  [creatorPubkeyHex],  // admins
);
// result = { group: {...}, welcome_rumors_json: [...] }

// List groups
const groups = mdk.getGroups();

// Get a specific group
const group = mdk.getGroup(mlsGroupIdHex);

// Members
const members = mdk.getMembers(mlsGroupIdHex);  // ["pubkey1", "pubkey2"]

// Add/remove members
const result = mdk.addMembers(mlsGroupIdHex, [keyPackageEvent]);
const result = mdk.removeMembers(mlsGroupIdHex, ["pubkey_hex"]);

// Update metadata
const result = mdk.updateGroupData(mlsGroupIdHex, {
  name: "New Name",
  description: "Updated description",
});

// Key rotation
const result = mdk.selfUpdate(mlsGroupIdHex);

// Leave
const result = mdk.leaveGroup(mlsGroupIdHex);

// Commit management
mdk.mergePendingCommit(mlsGroupIdHex);
mdk.clearPendingCommit(mlsGroupIdHex);
mdk.syncGroupMetadata(mlsGroupIdHex);

// Relays
const relays = mdk.getRelays(mlsGroupIdHex);
```

### Messages

```js
// Create an encrypted message
const event = mdk.createMessage(
  mlsGroupIdHex,
  senderPubkeyHex,
  "Hello, group!",
  9,                               // Nostr event kind
  [["p", "mentioned_pubkey"]],     // optional tags (null for none)
);
// event is a Nostr event object — publish to your relays

// Process incoming messages from relays
const result = mdk.processMessage(nostrEvent);
// result.type = "ApplicationMessage" | "Proposal" | "Commit" | ...

// Retrieve messages
const messages = mdk.getMessages(mlsGroupIdHex, {
  limit: 50,
  offset: 0,
  sortOrder: "created_at_first",  // or "processed_at_first"
});

const message = mdk.getMessage(mlsGroupIdHex, eventIdHex);
const latest = mdk.getLastMessage(mlsGroupIdHex, "created_at_first");
```

### Welcomes

```js
// Check for group invites
const welcomes = mdk.getPendingWelcomes({ limit: 10 });

const welcome = mdk.getWelcome(eventIdHex);

// Process a welcome from a Nostr event
const processed = mdk.processWelcome(wrapperEventIdHex, rumorObject);

// Accept or decline
mdk.acceptWelcome(welcomeObject);
mdk.declineWelcome(welcomeObject);
```

### Media (Free Functions)

These don't require an `Mdk` instance:

```js
import { prepareGroupImage, decryptGroupImage, deriveUploadKeypair } from "./src/index.js";

// Encrypt an image for upload
const prepared = prepareGroupImage(imageBytes, "image/png");
// prepared = { encrypted_data, encrypted_hash, image_key, image_nonce, ... }

// Decrypt a group image
const decrypted = decryptGroupImage(encryptedData, expectedHash, key, nonce);

// Derive upload keypair
const secretKeyHex = deriveUploadKeypair(imageKey, 2);
```

## Data Format

All complex return values (groups, messages, welcomes) are returned as **parsed JavaScript objects** — JSON serialisation is handled internally. You work with plain objects and arrays, never raw JSON strings.

## Runtime Support

| Runtime | Import | Requirement |
|---------|--------|-------------|
| **Bun** | `import { Mdk } from "./src/index.js"` | None |
| **Deno** | `import { Mdk } from "./src/mod.ts"` | `--allow-ffi` |

Node.js is not supported (no native FFI without N-API).

## Further Reading

- [Marmot Protocol Spec](https://github.com/marmot-protocol/marmot)
- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [Nostr Protocol](https://github.com/nostr-protocol/nostr)
- [C Bindings](https://github.com/marmot-protocol/mdk-cbindings) (the native layer)
