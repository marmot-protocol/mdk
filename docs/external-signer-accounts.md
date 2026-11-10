# External Signer Accounts

MDK supports external-signing accounts through host callbacks such as Amber/NIP-55
or an MDK-owned NIP-46 remote session. The user's Nostr secret stays with the signer.

External signer accounts are sign-capable accounts. They are different from
public/tracked accounts: MDK can publish, decrypt, receive welcomes, and run their
workers through a registered callback or a restored remote session.

## Account Model

`AccountSummary` exposes two signing flags:

- `local_signing`: MDK has a local Nostr secret for the account.
- `external_signing`: MDK has no local Nostr secret and uses an external signer.

Public/tracked accounts have both flags set to `false`.

An external account stores public account metadata and device-local database
unlock material. NIP-46 accounts also retain the communication credentials
described below, not the user's signing secret. A random SQLCipher key goes through the configured
`SecretStore` under the reserved `.external-sqlcipher/<account label>` credential,
with a SHA-256 identifier derived from that label. It is not the user's Nostr
private key and does not change the account's signing flags. Its storage protection
is the host's secret-store policy: an encrypted vault, a keychain, or the default
local-file backend.

An existing `.external-sqlcipher-secret` file is migrated on first open. MDK
verifies the secret-store write before scrubbing and removing the old file. If an
existing database has neither credential, opening fails rather than generating a
different key and losing access to the database.

The database secret feeds the per-database HKDF derivation; the resulting 32 bytes
use SQLCipher raw-key presentation. Existing passphrase-keyed databases undergo
the same crash-safe rekey as local-signing accounts. Retain the secret-store
credential and `.salt` sidecars for recovery or downgrade. See the
[key-format migration and offline CLI/downgrade procedure](marmot-architecture/storage-format-v2.md#sqlcipher-key-presentation-and-kdf-work-factor-decision-record-mdk1791).

## Client Flow

For a new host-callback account, clients call `loginExternalSigner` with:

- the account public key as hex or npub
- an `ExternalAccountSignerFfi` callback implementation
- default relays
- bootstrap relays

For an existing host-callback account after app/process restart, clients must
call `registerExternalSigner` before expecting the account to publish, decrypt,
receive welcomes, or start its worker. MDK lists the account before the callback
is registered, but runtime work remains paused until registration succeeds.

Registration activates the worker and reuses its validated, stored current-profile
account-identity proof. A missing or unusable proof requires a new signature; a
successful acquisition is persisted for subsequent process restarts. Keep
registration off the UI thread. Start local accounts first, then connect and register
each external account independently so an unavailable signer does not hold up
other accounts. Replacing a callback updates the existing per-account signer slot;
SDK clients and workers keep the same pinned identity.

If a reversibly signed-out external account logs in again through
`loginExternalSigner`, MDK clears the signed-out marker after setup succeeds and
then reconciles the runtime worker.

## NIP-46 sessions

`MarmotAppRuntime::nip46_new` prepares an offline session from a `bunker://` URI
or a relay list for client-initiated pairing. Review `review_permissions`, obtain
user consent, and approve that exact version and grant list. Imported credential
exports also need approval; their JSON cannot grant permissions by itself.

For client-initiated pairing, await `pairing_offer` before displaying its
`nostrconnect://` URI. The call waits for relay subscription acknowledgements so
an ephemeral signer response can arrive before `connect` starts. Display the URI
only after that call succeeds, then await `connect` concurrently with the pairing
UI. The offline `uri` accessor alone does not install a listener. An interrupted
unpaired offer gets a fresh secret; display the replacement offer, not the old QR.
Only relays with acknowledged listeners appear in the returned offer; an offline
configured relay does not prevent pairing through a ready relay.
Later offers retry the configured endpoints rather than permanently dropping them.

For a bunker URI, call `connect` directly. Both paths verify `get_public_key`
and pin the user key separately from the remote signer and communication keys.
`nip46_login` binds that verified user to an account and persists its session
before account setup asks for signatures. `nip46_register` attaches an imported
session to an existing account. Only one communication key can own an account,
and a bound communication key cannot be imported into another session.
Before setup commits, a failed handoff restores the prior callback and stored
grant record; only credentials created by that attempt are removed.
Already-attached sessions remain bound. For an active account without a prior
callback, possibly exposed publication retains its pairing for restart retry.
Journal cleanup errors do not revoke a network-ready account.
Account setup transactions share the app's signer-registry scope across runtime handles.

MDK stores the communication secret through `AccountSecretStore` under
`.nip46-client/<account label>`, with a separate SHA-256-derived credential id.
The private `.nip46-session.json` contains public keys, relays, a client name,
and the approved permission snapshot, never the secret or one-use bunker token.
The communication key, SQLCipher credential, and user's signing key are distinct.
A crash before the first secret-store write can leave metadata without a key.
Restoration reports the missing key; explicit approved pairing can repair that
state after a credential load confirms absence. An unavailable or malformed key
does not permit repair. An existing key is never overwritten.

Runtime startup restores each stored session before reconciling account workers.
Restoration is local; later signer work reconnects with a 90-second request
deadline and a queue capped at 32 operations. Stored valid account-identity proofs
remain reusable offline. A missing proof can require remote signing. Corrupt or
unavailable session material leaves the account intact and reports a recoverable
error. `nip46_resume` returns the account's session without a host callback or
exported descriptor, and can rebuild a terminally cancelled actor from storage.

Permission version 1 covers these MDK capabilities:

| Capability | Requested grants |
| --- | --- |
| Account-identity and push-owner proofs | `sign_event:450`, `sign_event:451` |
| KeyPackages and deletion | `sign_event:30443`, `sign_event:5` |
| NIP-59 seals and relay authentication | `sign_event:13`, `sign_event:22242` |
| Relay lists | `sign_event:10002`, `sign_event:10050` |
| Profiles, follows, and mute lists | `sign_event:0`, `sign_event:3`, `sign_event:10000` |
| Blossom authorization and backup pointers | `sign_event:24242`, `sign_event:30078` |
| Welcome and encrypted account data | `nip44_encrypt`, `nip44_decrypt` |

NIP-04 and unrestricted `sign_event` are not requested. A restored snapshot that
differs from the required set blocks RPCs until reviewed and approved again;
startup never broadens it. Client approval is not signer authorization: the signer
can still reject any request or ask for authentication.

Status exposes typed state and error codes, a session generation, and the active
request id. `auth_url` is an intermediate challenge for that request. Open it in
the host UI; `complete_auth` acknowledges the matching challenge but cannot finish
the RPC. Only a correlated final response from the pinned signer can do that.
Never log status snapshots containing authentication URLs, pairing URIs, exports,
or request payloads.

Request-scoped cancellation, including dropping an async signer call, retires
that request without cancelling another account. `disconnect` interrupts the
current generation and permits explicit reconnect. `cancel` is terminal for that
actor. `connect` does not preempt another RPC; use `disconnect` before reconnecting
when an old offline request is still pending. Delayed responses cannot revive a
cancelled generation. `logout` attempts a five-second
courtesy request and erases local communication credentials regardless of the
remote result. Account sign-out, session removal, and wipe erase the key without
requiring the signer; encrypted history and its database credential remain on
reversible sign-out. `shutdown_and_close` cancels actors but preserves stored
sessions. Delete any host-owned credential backups on logout too.
If vault deletion fails, signing stays stopped and cleanup ownership remains
retryable. Retry local erasure or `nip46_remove` after the vault recovers; pending
removal cannot restore or authorize a signer.

Generic host-callback/NIP-55 sign-out does not query the NIP-46 credential
namespace when no session record exists; generic account wipe follows the same rule.
Explicit NIP-46 removal also revokes an orphaned communication key if its metadata
was lost, retaining a removal intent when vault deletion fails.

Every signer relay passes the shared retired-relay and endpoint policy and uses
the configured process proxy. It retains the documented
[Nostr SDK DNS-resolution residual](marmot-architecture/overview/dial-safety.md#accepted-residual).
See the [UniFFI lifecycle](../crates/marmot-uniffi/README.md#nip-46-accounts) and
[C ownership rules](../crates/marmot-c/README.md#nip-46-accounts).

## Amber-Compatible Account-Identity Proof

The MDK account-identity proof must be signable by platform signers that only
support Nostr-event signing. Amber / NIP-55 signers can sign canonical Nostr
events, but they do not expose an arbitrary raw-digest Schnorr signing
operation.

That means a callback surface that requires raw proof-digest signing cannot be
implemented by Amber without creating a broken account. The proof is on the MLS
hot path: KeyPackage publication, group creation, group joins, and leaf updates
can all need it.

MDK therefore uses an Amber-compatible event-signing shape: it constructs a
canonical, unpublished Nostr proof event from the known proof inputs, asks the
external signer to sign it through `signEvent`, and embeds/verifies the
resulting signature in the MLS proof. The verifier reconstructs the same
unsigned event from the MLS leaf/proof context. This is proof version 2; version
1 was the previous raw-prehash scheme and is intentionally not accepted by this
contract.

Clients should still fail account setup with a typed signer error if the
platform signer cannot sign the proof event.

## Callback Surface

`ExternalAccountSignerFfi` must provide:

- `publicKey()`: returns the signer account public key as hex or npub.
- `signEvent(unsignedEventJson)`: signs a serialized unsigned Nostr event and
  returns the full signed event JSON.
- `nip44Encrypt(publicKey, content)` / `nip44Decrypt(publicKey, payload)`.
- `nip04Encrypt(publicKey, content)` / `nip04Decrypt(publicKey, payload)`.

The account-identity proof is signed through `signEvent` using a canonical,
unpublished Nostr event. MDK stores/verifies the resulting event signature in
the MLS proof. The proof still binds the Nostr account key to the MLS leaf key,
but the signing operation is now compatible with standard external signers that
only support Nostr-event signing.

NIP-04 support is currently exposed for legacy Nostr signer compatibility, not
for a required MDK protocol path. If a client platform cannot provide NIP-04, it
should return a clear unsupported signer error from those methods; MDK client
integrations should not silently pretend encryption/decryption succeeded.

## Runtime Operations That May Prompt The Signer

Clients should expect signer callbacks during:

- login setup and signer registration (`publicKey`)
- account identity proof generation for KeyPackage publication, group creation,
  group joins, and MLS leaf updates (`signEvent`)
- NIP-42 relay authentication and any Nostr transport event publish (`signEvent`)
- relay-list, KeyPackage, user metadata, and follow-list publication (`signEvent`)
- push registration/removal owner proofs and notification triggers (`signEvent`)
- Blossom/media upload authorization events (`signEvent`)
- welcome wrapping/decryption or other encrypted app-data paths that require
  Nostr encryption/decryption (`nip44Encrypt` / `nip44Decrypt`)

The exact number of prompts depends on the platform signer. For Amber-like
signers, clients should use the signer's permission/remember model where
available; otherwise normal account startup and messaging may produce repeated
prompts. Clients should not silently retry after `ExternalSignerRejected` unless
the user explicitly starts the action again.

## Error Contract

MDK exposes typed errors for the client-significant external signer states:

- `ExternalSignerUnavailable`: the account requires an external signer callback
  but none is registered in this runtime process.
- `ExternalSignerMismatch`: the registered signer returned a different public
  key than the account being opened.
- `ExternalSignerRejected`: the user rejected/cancelled an external signer
  prompt. MDK reports it the same way wherever the rejection happens: opening
  the account, signing an identity proof for a KeyPackage or group change, or
  publishing an event.

Other callback failures may surface as runtime, publish, or transport failures,
especially if the Nostr SDK erases the original signer error while publishing to
relays. Client integrations should treat `ExternalSignerRejected` as retryable
user cancellation, not account corruption.

## Identity Pinning

MDK validates the external signer public key at registration time and stores a
pinned registered signer wrapper. Runtime calls use that wrapper, not the
callback's self-reported key, so a stale or swapped callback cannot silently
become another account. Signed events and account-identity proof requests are
checked against the registered account key.
