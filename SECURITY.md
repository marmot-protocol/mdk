# Security

This document describes MDK's security posture, the measures we've taken to protect sensitive data, and guidance for secure deployment.

## Reporting a Vulnerability

To report security issues, send an email to **<j@ipf.dev>**. Please do not open public issues for security vulnerabilities.

## Security Overview

MDK implements the [Marmot Protocol](https://github.com/marmot-protocol/marmot), which combines MLS (Messaging Layer Security, RFC 9420) with Nostr for secure group messaging. The security of MDK depends on:

1. **MLS Protocol Security**: Forward secrecy, post-compromise security, and group key agreement
2. **Data-at-Rest Protection**: Encryption of stored MLS state using SQLCipher
3. **Key Management**: Secure storage of encryption keys in platform-native credential stores
4. **File System Hardening**: Restrictive permissions on database files

## Threat Model

### Assets Protected

- **MLS state**: Group keys, epoch secrets, and cryptographic material
- **Exporter secrets**: These enable retrospective traffic decryption if compromised
- **Message content**: Decrypted messages stored in the database
- **Group metadata**: Member lists, admin keys, and group configuration

### Primary Threat: Offline Data Exfiltration

MDK's encryption-at-rest protections are designed to defend against an attacker who:

- Obtains a copy of the SQLite database files (e.g., via device theft, filesystem exfiltration, misconfigured backups, or overly permissive file permissions)
- Does **not** have access to the platform's secure credential storage (Keychain, Keystore, etc.)
- Does **not** control the running application process

### Out of Scope

The following threats are **not** defended by MDK's current implementation:

- Compromised host application (malicious app integration)
- Compromised device/OS (root, jailbreak, or malware with memory access)
- Side-channel attacks or hardware-level attacks
- "Evil maid" attacks that tamper with the runtime environment

### Metadata Privacy and Group Identifier Protection

MDK follows [MIP-01](https://github.com/marmot-protocol/marmot) group identity and privacy guidance. The following identifiers are considered privacy-sensitive and must not be exposed in logs, error messages, or debug output:

| Identifier | Description | Why It's Sensitive |
|------------|-------------|-------------------|
| Encryption keys | Any key material | Cryptographic data enabling decryption |
| Exporter secrets | MLS exporter secrets | Enable retrospective traffic decryption |
| `mls_group_id` | MLS group identifier (32 bytes) | Enables cross-system group linkage and tracking |
| `nostr_group_id` | Nostr group identifier | Links Nostr events to MLS groups |

**Attack Scenario**: An attacker or operator with access to logs could exfiltrate these identifiers, allowing cross-system linkage of groups and weakening metadata privacy guarantees. Even without an active attacker, routine logging may leak identifiers to remote analytics or crash reporting backends.

See also: `AGENTS.md` for contributor guidelines on avoiding identifier leakage

## Encryption at Rest

MDK uses [SQLCipher](https://www.zetetic.net/sqlcipher/) for transparent encryption of all SQLite databases. This is enabled by default for production use.

### SQLCipher Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| Encryption Algorithm | AES-256-CBC | Industry-standard symmetric encryption |
| Key Derivation | Raw 256-bit key | No passphrase KDF; keys are pre-generated |
| Page Authentication | HMAC-SHA512 | Integrity protection for each database page |
| Cipher Compatibility | SQLCipher 4.x | Pinned via `PRAGMA cipher_compatibility = 4` |
| Temporary Storage | Memory only | `PRAGMA temp_store = MEMORY` on every connection |

### Encrypted File Types

SQLCipher encrypts the following files:

- Main database file (`*.db`)
- Write-ahead log (`*-wal`) - page data is encrypted
- Rollback journal (`*-journal`) - page data is encrypted

**Note**: The rollback journal header and master journal are not encrypted but do not contain user data.

## Key Management

MDK integrates with the [`keyring-core`](https://crates.io/crates/keyring-core) ecosystem for secure credential storage. Encryption keys are stored in platform-native credential stores:

| Platform | Credential Store |
|----------|------------------|
| macOS | Keychain Services |
| iOS | Keychain Services |
| Android | Android Keystore |
| Windows | Credential Manager |
| Linux | Kernel keyutils or D-Bus Secret Service |

### Key Generation

- Keys are 256-bit (32 bytes) generated using `getrandom` (cryptographically secure)
- Keys are generated once per database and stored in the platform keyring
- Keys are never logged or exposed in debug output (`EncryptionConfig` redacts keys)

### Key Identifiers

When using automatic key management, two identifiers are required:

- **Service ID**: Application identifier (e.g., `com.example.myapp`)
- **Key ID**: Database-specific identifier (e.g., `mdk.db.key.default`)

These identifiers are not secret; they are indexes into the secure storage.

## File System Hardening

MDK applies restrictive file permissions to database files:

### Unix (macOS, Linux, iOS, Android)

| Resource | Permissions | Description |
|----------|-------------|-------------|
| Database directory | `0700` | Owner read/write/execute only |
| Database files | `0600` | Owner read/write only |
| Sidecar files (`-wal`, `-shm`, `-journal`) | `0600` | Owner read/write only |

#### Sidecar File Permissions (Defense in Depth)

SQLite creates sidecar files (`-wal`, `-shm`, `-journal`) dynamically during database operations. MDK applies restrictive permissions to these files if they exist when the storage is initialized, but files created afterward may temporarily have default (umask-dependent) permissions until the next `MdkSqliteStorage` instance is created.

This is acceptable due to MDK's layered security approach:

1. **Directory permissions**: The parent directory has `0700` permissions. Even if sidecar files have more permissive defaults, other users cannot traverse into the directory to access them.

2. **SQLCipher encryption**: All data in sidecar files is encrypted. The `-wal` and `-journal` files contain encrypted page data, unreadable without the encryption key.

3. **Mobile sandboxing**: On iOS/Android, the app sandbox is the primary security boundary.

Alternative approaches like `PRAGMA journal_mode = MEMORY` were rejected because they sacrifice crash durability, which is unacceptable for MLS cryptographic state.

### Windows

MDK does **not** currently harden Windows filesystem permissions for database paths. Windows uses Access Control Lists (ACLs), and doing this correctly requires careful handling of:

- Inherited ACEs (disabling inheritance / “protected DACL”)
- Explicit allow/deny ordering and effective permissions
- The intended security principals to allow (e.g., current user vs `SYSTEM` vs `Administrators`)

**Host responsibility (recommended):**

- Store databases in per-user, app-private locations (e.g., `%LOCALAPPDATA%\\<app_name>\\`)
- Apply an ACL that restricts access to the intended principals (at minimum, the current user)
- Disable inheritance on the database directory so newly created sidecar files (`-wal`, `-shm`, `-journal`) do not accidentally inherit broader access

MDK still encrypts database contents with SQLCipher on Windows; this section is specifically about **filesystem access control**.

### Mobile Platforms

On iOS and Android, the application sandbox provides the primary security boundary. MDK still applies restrictive permissions as defense-in-depth.

## Compile-Time Hardening (Optional)

### Temporary Storage Hardening

By default, `libsqlite3-sys` compiles SQLCipher with `SQLITE_TEMP_STORE=2`, which stores temporary files in memory by default but allows runtime override. MDK sets `PRAGMA temp_store = MEMORY` on every connection to ensure temp files stay in memory.

For maximum hardening, you can force all temporary storage to memory at compile time:

```bash
export LIBSQLITE3_FLAGS="SQLITE_TEMP_STORE=3"
cargo build --release
```

With `SQLITE_TEMP_STORE=3`, temporary files are **always** in memory, regardless of any runtime settings.

**Note**: Android builds already use `SQLITE_TEMP_STORE=3` by default in `libsqlite3-sys`.

### Trade-offs

| Setting | Security | Memory Usage | Override at Runtime? |
|---------|----------|--------------|---------------------|
| `=2` (default) + `PRAGMA temp_store = MEMORY` | High | Normal | Theoretically yes (but MDK sets the PRAGMA) |
| `=3` (compile-time) | Highest | May be higher | No |

For most deployments, the default configuration with MDK's runtime PRAGMA is sufficient. Use `SQLITE_TEMP_STORE=3` for environments requiring defense-in-depth against runtime tampering.

## Secure Deployment Checklist

### Production Requirements

- [ ] Initialize platform keyring store before creating MDK storage
- [ ] Use `MdkSqliteStorage::new()` or `new_mdk()` (encrypted by default)
- [ ] Store databases in app-private directories
- [ ] Never use `new_unencrypted()` in production
- [ ] Ensure database backups are also encrypted or stored securely

### Development / Testing

- `MdkSqliteStorage::new_unencrypted()` is available but logs a warning
- In-memory databases (`:memory:`) are not encrypted (appropriate for tests)
- Use `new_with_key()` if you need to test with a specific key

## Current Limitations

### Not Yet Implemented

- **Database migration**: No utility to migrate from unencrypted to encrypted databases
- **Re-keying**: No utility to change the encryption key of an existing database
- **In-memory zeroization**: Secrets may remain in process memory after use

### Trust Boundaries

MDK trusts:

- The `keyring-core` ecosystem and platform-native credential stores
- The host application to initialize the keyring store correctly
- The host application to not expose decrypted data

## References

- [MLS Protocol (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html)
- [MLS Architecture (RFC 9750)](https://www.rfc-editor.org/rfc/rfc9750.html)
- [SQLCipher Design](https://www.zetetic.net/sqlcipher/design/)
- [keyring-core Ecosystem](https://github.com/open-source-cooperative/keyring-rs)
- [Marmot Protocol](https://github.com/marmot-protocol/marmot)
