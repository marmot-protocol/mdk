# External Signer Accounts

MDK supports account records whose Nostr private key is owned by a host-provided
external signer instead of MDK's local secret store. This is intended for client
integrations such as Android Amber / NIP-55, iOS secure signer integrations, and
desktop signer bridges.

External signer accounts are sign-capable accounts. They are different from
public/tracked accounts: MDK can publish, decrypt, receive welcomes, and run the
account worker only after the client registers a signer callback for the account.

## Account Model

`AccountSummary` exposes two signing flags:

- `local_signing`: MDK has a local Nostr secret for the account.
- `external_signing`: MDK has no local Nostr secret and must call a client
  signer callback.

Public/tracked accounts have both flags set to `false`.

An external account stores only public account metadata plus device-local
database unlock material. The `.external-sqlcipher-secret` file is local
SQLCipher key material for opening this device's account database. It is not the
Nostr private key and cannot sign Nostr events. It is protected at the app
sandbox/filesystem-permission tier, not by the external signer or hardware
keystore.

## Client Flow

For a new external signer account, clients call `loginExternalSigner` with:

- the account public key as hex or npub
- an `ExternalAccountSignerFfi` callback implementation
- default relays
- bootstrap relays

For an existing external signer account after app/process restart, clients must
call `registerExternalSigner` before expecting the account to publish, decrypt,
receive welcomes, or start its worker. MDK lists the account before the callback
is registered, but runtime work remains paused until registration succeeds.

If a reversibly signed-out external account logs in again through
`loginExternalSigner`, MDK clears the signed-out marker after setup succeeds and
then reconciles the runtime worker.

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
  prompt.

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
