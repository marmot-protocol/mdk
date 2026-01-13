# 🦫 MDK - Marmot Development Kit

**A Rust implementation of the Marmot Protocol for secure, decentralized group messaging**

![CI](https://github.com/marmot-protocol/mdk/actions/workflows/ci.yml/badge.svg)
![Coverage](https://github.com/marmot-protocol/mdk/actions/workflows/coverage.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](https://opensource.org/licenses/MIT)

MDK is a Rust library that implements the [Marmot Protocol](https://github.com/marmot-protocol/marmot), bringing together the [MLS (Messaging Layer Security) Protocol](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr's](https://github.com/nostr-protocol/nostr) decentralized network to enable secure group messaging without centralized servers.

## 🚀 Features

- **🔒 End-to-End Encryption**: Messages encrypted using the MLS protocol with forward secrecy and post-compromise security
- **🌐 Decentralized**: Built on Nostr's distributed relay network - no central servers required
- **👥 Group Messaging**: Secure group creation, member management, and messaging
- **🔑 Key Management**: Automatic key package generation, rotation, and distribution
- **💾 Flexible Storage**: Pluggable storage backends (in-memory, SQLite, custom)
- **📱 Media Support**: Optional encrypted media sharing (images, files) with MIP-04
- **🛡️ Metadata Protection**: Hides communication patterns and group membership
- **⚡ Performance**: Efficient cryptographic operations and message processing

## 📦 Architecture

MDK is organized into several crates for modularity and flexibility:

### Core Crates

- **`mdk-core`**: Main library with MLS implementation and Nostr integration
- **`mdk-storage-traits`**: Storage abstraction layer and trait definitions

### Storage Providers

- **`mdk-memory-storage`**: In-memory storage for testing and development
- **`mdk-sqlite-storage`**: SQLite-based persistent storage with migrations

## 🔐 OpenMLS Integration

MDK is built on top of [OpenMLS](https://github.com/openmls/openmls), a robust Rust implementation of the MLS protocol. OpenMLS provides the cryptographic foundation while MDK adds Nostr-specific functionality and abstractions.

### What OpenMLS Provides

- **MLS Protocol Implementation**: Full RFC 9420 compliance with all cryptographic operations
- **Group Management**: Creating, updating, and managing MLS groups
- **Key Management**: Automatic key rotation, forward secrecy, and post-compromise security
- **Message Processing**: Encryption, decryption, and authentication of group messages
- **Extensibility**: Support for MLS extensions (which MDK uses for Nostr integration)

### How MDK Uses OpenMLS

```rust
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;

// MDK wraps OpenMLS with Nostr-specific functionality
pub struct MdkProvider<Storage> {
    crypto: RustCrypto,           // OpenMLS crypto provider
    storage: Storage,             // Custom storage abstraction
}

impl<Storage> OpenMlsProvider for MdkProvider<Storage> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage;  // Storage directly implements StorageProvider<1>
    // ... implementation details
}
```

### Key OpenMLS Components in MDK

- **`MlsGroup`**: Core group management (wrapped by MDK's group handling)
- **`KeyPackage`**: Identity and key distribution (published as Nostr events)
- **`Welcome`**: Group invitation messages (sent via Nostr's gift-wrap)
- **`MlsMessageOut`**: Encrypted group messages (published as Nostr events)
- **`Credential`**: Identity verification (integrated with Nostr keys)

### Ciphersuite and Extensions

MDK configures OpenMLS with specific settings for Nostr compatibility:

```rust
// Default ciphersuite for all MDK groups
const DEFAULT_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// Required extensions for Nostr integration
const REQUIRED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::ApplicationId,
    ExtensionType::RatchetTree,
    ExtensionType::RequiredCapabilities,
    ExtensionType::Unknown(0xF2EE), // Marmot Group Data Extension
];
```

This ensures all MDK groups use compatible cryptography and include necessary Nostr-specific metadata.

## 🔧 Installation

Add MDK to your `Cargo.toml`:

```toml
[dependencies]
mdk-core = "0.5.0"
mdk-memory-storage = "0.5.0"  # For in-memory storage
# OR
mdk-sqlite-storage = "0.5.0"  # For persistent SQLite storage
```

### Feature Flags

- **`mip04`**: Enable encrypted media support (images, files)

```toml
[dependencies]
mdk-core = { version = "0.5.0", features = ["mip04"] }
```

## 🚀 Quick Start

Here's a basic example of creating a group and sending messages:

```rust
use mdk_core::prelude::*;
use mdk_memory_storage::MdkMemoryStorage;
use nostr::{Keys, Kind, RelayUrl};
use nostr::event::builder::EventBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate identities
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();

    // Create MDK instances
    let alice_mdk = MDK::new(MdkMemoryStorage::default());
    let bob_mdk = MDK::new(MdkMemoryStorage::default());

    let relay_url = RelayUrl::parse("wss://relay.example.com")?;

    // Bob creates a key package
    let (bob_key_package, tags) = bob_mdk
        .create_key_package_for_event(&bob_keys.public_key(), [relay_url.clone()])?;

    let bob_key_package_event = EventBuilder::new(Kind::MlsKeyPackage, bob_key_package)
        .tags(tags)
        .build(bob_keys.public_key())
        .sign(&bob_keys)
        .await?;

    // Alice creates a group with Bob
    let config = NostrGroupConfigData::new(
        "Alice & Bob".to_string(),
        "Private chat".to_string(),
        None, // image_hash
        None, // image_key
        None, // image_nonce
        vec![relay_url],
        vec![alice_keys.public_key(), bob_keys.public_key()],
    );

    let group_result = alice_mdk.create_group(
        &alice_keys.public_key(),
        vec![bob_key_package_event],
        config,
    )?;

    // Bob processes the welcome message
    let welcome_rumor = &group_result.welcome_rumors[0];
    bob_mdk.process_welcome(&nostr::EventId::all_zeros(), welcome_rumor)?;

    let welcomes = bob_mdk.get_pending_welcomes()?;
    bob_mdk.accept_welcome(&welcomes[0])?;

    // Alice sends a message
    let message_rumor = EventBuilder::new(Kind::Custom(9), "Hello Bob!")
        .build(alice_keys.public_key());

    let message_event = alice_mdk.create_message(
        &group_result.group.mls_group_id,
        message_rumor
    )?;

    // Bob processes the message
    bob_mdk.process_message(&message_event)?;

    println!("Message sent and received successfully!");
    Ok(())
}
```

## 💾 Storage Options

### In-Memory Storage (Development)

```rust
use mdk_memory_storage::MdkMemoryStorage;

let mdk = MDK::new(MdkMemoryStorage::default());
```

### SQLite Storage (Production)

For production use, the recommended approach uses automatic key management with `keyring-core`.
First, initialize your platform's keyring store, then create the MDK instance:

```rust,ignore
use mdk_sqlite_storage::MdkSqliteStorage;

// First, initialize platform keyring (once at app startup)
// e.g., keyring_core::set_default_store(AppleStore::new());

// MDK handles key generation and secure storage automatically
let storage = MdkSqliteStorage::new(
    "path/to/database.db",
    "com.example.myapp",      // Service identifier
    "mdk.db.key.default"      // Key identifier
)?;
let mdk = MDK::new(storage);
```

If you need to manage encryption keys yourself:

```rust
use mdk_sqlite_storage::{MdkSqliteStorage, EncryptionConfig};

let key = [0u8; 32]; // Your securely stored 32-byte key
let config = EncryptionConfig::new(key);
let storage = MdkSqliteStorage::new_with_key("path/to/database.db", config)?;
let mdk = MDK::new(storage);
```

For development/testing only (unencrypted):

```rust
use mdk_sqlite_storage::MdkSqliteStorage;

// ⚠️ WARNING: Unencrypted - for development only
let storage = MdkSqliteStorage::new_unencrypted("path/to/database.db")?;
let mdk = MDK::new(storage);
```

### Custom Storage

Implement the `MdkStorageProvider` trait for custom storage backends:

```rust
use mdk_storage_traits::MdkStorageProvider;

struct MyCustomStorage;

impl MdkStorageProvider for MyCustomStorage {
    // Implement required methods
}
```

## 🖼️ Encrypted Media (MIP-04)

Enable the `mip04` feature for encrypted media support:

```rust
#[cfg(feature = "mip04")]
use mdk_core::encrypted_media::*;

// Encrypt and upload media
let media_manager = EncryptedMediaManager::new();
let encrypted_media = media_manager.encrypt_image(&image_bytes)?;
```

## 🔍 Examples

Check out the [`examples/`](crates/mdk-core/examples/) directory for complete working examples:

- [`mls_memory.rs`](crates/mdk-core/examples/mls_memory.rs): Full group messaging workflow with in-memory storage
- [`mls_sqlite.rs`](crates/mdk-core/examples/mls_sqlite.rs): Persistent storage example with SQLite

Run examples with:

```bash
cargo run --example mls_memory
cargo run --example mls_sqlite
```

## 🧪 Testing

We recommend using [just](https://github.com/casey/just) for running tests and development tasks:

```bash
# Run all tests with all features (recommended)
just test

# Run tests without optional features
just test-no-features

# Run tests with only mip04 feature
just test-mip04

# Run all test combinations (like CI)
just test-all
```

You can also use cargo directly:

```bash
# Run all tests
cargo test

# Run tests with encrypted media support
cargo test --features mip04

# Run tests for specific crate
cargo test -p mdk-core
```

### Test Coverage

Check test coverage across all crates:

```bash
# Generate coverage summary
just coverage

# Generate HTML coverage report
just coverage-html
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#test-coverage) for detailed coverage documentation.

## 📚 Documentation

- **API Documentation**: [docs.rs/mdk-core](https://docs.rs/mdk-core)
- **Marmot Protocol**: [github.com/marmot-protocol/marmot](https://github.com/marmot-protocol/marmot)
- **MLS Specification**: [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- **OpenMLS Library**: [github.com/openmls/openmls](https://github.com/openmls/openmls) - The MLS implementation we build upon
- **Nostr Protocol**: [github.com/nostr-protocol/nostr](https://github.com/nostr-protocol/nostr)

## 🛠️ Development

### Prerequisites

- Rust 1.90.0 or later
- SQLite (for sqlite storage tests)
- [just](https://github.com/casey/just) (recommended for development)

### Building

```bash
git clone https://github.com/marmot-protocol/mdk.git
cd mdk
cargo build
```

### Development Commands (justfile)

We use [just](https://github.com/casey/just) as a command runner for development tasks. Install it with:

```bash
# macOS
brew install just

# Other platforms: https://github.com/casey/just#installation
```

Available commands:

```bash
# List all available commands
just

# Testing
just test              # Run tests with all features
just test-no-features  # Run tests without optional features
just test-mip04        # Run tests with only mip04 feature
just test-all          # Run all test combinations (like CI)

# Code Quality
just lint              # Run clippy with all features
just lint-no-features  # Run clippy without optional features
just lint-mip04        # Run clippy with only mip04 feature
just lint-all          # Run clippy for all feature combinations
just fmt               # Check code formatting
just docs              # Check documentation

# Comprehensive Checks
just check             # Run all checks (like CI)
just check-full        # Full comprehensive check with all feature combinations
```

The justfile ensures consistent testing across different feature combinations, which is especially important for optional features like `mip04`.

## 🤝 Contributing

We welcome contributions! Please see our [contributing guidelines](CONTRIBUTING.md) and:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the full test suite: `just check-full`
6. Submit a pull request

**Before submitting a PR**, ensure all checks pass:

```bash
# Run comprehensive checks (recommended)
just check-full

# Or run individual checks
just fmt       # Check formatting
just lint-all  # Check all clippy combinations
just test-all  # Run all test combinations
just docs      # Check documentation
```

### Security

For security issues, please email **<j@ipf.dev>** instead of opening a public issue.

## ⚠️ Status

**MDK is currently in ALPHA status.** While functional, the API may change in breaking ways. Use in production is not recommended until the library reaches stable status.

Current implementations are suitable for:
- Research and development
- Proof-of-concept applications
- Contributing to protocol development
- Educational purposes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[OpenMLS](https://github.com/openmls/openmls)**: The robust MLS protocol implementation that powers MDK's cryptographic operations
- **[rust-nostr](https://github.com/rust-nostr/nostr)**: Comprehensive Nostr protocol support and event handling
- **[OpenMLS Team](https://github.com/openmls)**: For their excellent work on MLS protocol implementation and storage abstractions
- **MLS Working Group**: For developing the MLS specification (RFC 9420)
- **Nostr Community**: For creating a truly decentralized communication protocol

## 🔗 Related Projects

- [whitenoise](https://github.com/marmot-protocol/whitenoise): Flutter app using whitenoise
- [whitenoise-rs](https://github.com/marmot-protocol/whitenoise-rs): Rust crate that implements Marmot for the White Noise app
- [marmot-ts](https://github.com/marmot-protocol/marmot-ts): TypeScript implementation of Marmot

---

Built with ❤️ for a more private and decentralized future.
