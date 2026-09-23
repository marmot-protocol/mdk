# Complete MarmotKit method reference

This reference inventories the UniFFI exports in the 0.10.2 source baseline and is maintained
alongside source changes. Start with the [integration guide](README.md#integration-guide-and-api-reference)
for API selection, lifecycle, localization and ownership. For this release's changes, read
[0.10.1 → 0.10.2](../../docs/integration/0.10.2.md).

This inventories runtime/object methods, free functions and host callback methods. `AttachmentHistoryCursor` is an opaque object with no exported
methods. Generated disposal/concurrency helpers are platform scaffolding, not additional
MDK commands. C has a separate [complete symbol index](../marmot-c/API-REFERENCE.md), including
its lifetime helpers and compatibility-only entry points.

## Reading the reference

- Signatures below use exact Rust export spelling and types; Swift/Kotlin normally expose
  lowerCamelCase names (`attachment_local_assets` → `attachmentLocalAssets`). Constructors
  and native integer/optional/list/error syntax follow generated code from your cohort.
- `async fn` becomes Swift async / Kotlin suspend. A synchronous `fn` can perform storage
  I/O; run blocking operations off the UI thread. `Result` becomes the generated error path;
  `Option` is successful absence/stream closure as specified by the individual contract.
- **Current** means supported for its stated purpose, not that every app needs it.
  **Lower-level** means an intentional custom-client/primitive surface.
  **Compatibility** means a newer path is recommended for that listed use case; it is not
  a formal deprecation annotation, removal promise or requirement to rewrite custom clients.
  **Host callback** means implement it in the host, not call it as a runtime command.
- Source links lead to signatures, full doc comments and implementations. DTO field/variant
  definitions live in [conversions](src/conversions/), [errors](src/errors.rs),
  [Markdown types](src/markdown.rs) and the generated binding from the same release.
  Per-feature contracts in the README override no source behavior; report discrepancies.
- Object methods use their owning type explicitly. Distinguish each `next`/`snapshot` contract:
  a transfer subscription delivers its initial value from `next`, while a screen window
  has a separate initial snapshot. Do not infer cancellation support from another handle.

## Maintaining the reference

Run `just binding-docs-update` to refresh exact signatures and source anchors without
rewriting the surrounding guidance. New exports receive blocking scaffolds for an author
to complete and organize; removed/duplicate entries need explicit editorial cleanup.
`just binding-docs-gate` checks that metadata and runs the companion regression tests.
Descriptions and API-selection recommendations still require source-aware human review;
they are not verified by the mechanical gate. Counts are reported by the tool rather than
hard-coded in these pages.

## Methods by source module

Each expandable section lists every export in that module. Search this page for the exact
Rust or owning-type method name. Signatures are kept intact to make input/output, optionality,
synchronous versus asynchronous behavior and drift review explicit.

<details>
<summary>commands/account.rs</summary>

### `Marmot::list_accounts`

**Current.**

```rust
pub fn list_accounts(&self) -> Result<Vec<AccountSummaryFfi>, MarmotKitError>
```

All accounts known to the runtime, in stable order. `running` is `false` for accounts that haven't been brought up by the current process yet.

[Source](src/commands/account.rs#L24)

### `Marmot::account_unread_summary`

**Lower-level.** One-shot unread query; prepared account badges use subscribe_account_attention.

```rust
pub fn account_unread_summary( &self, ) -> Result<Vec<conversions::AccountUnreadFfi>, MarmotKitError>
```

Per-account unread aggregate for the account-switcher and application badge (mdk#461, mdk#1460). Each entry is read from that account's materialized chat-list projection, so this does not require switching into, or loading a full session/timeline for, any account — non-active (not-`running`) local-signing accounts are reported too. This legacy getter omits accounts whose projection read fails. `attention_only_conversations` counts each active pending invitation once and accepted manual-only reminders, without overlapping message totals. Archived chats and departed or departing groups contribute nothing.

[Source](src/commands/account.rs#L48)

### `Marmot::remove_account`

**Current.**

```rust
pub async fn remove_account(&self, account_ref: String) -> Result<(), MarmotKitError>
```

Remove a local-signing account from this device.

[Source](src/commands/account.rs#L60)

### `Marmot::sign_out_and_wipe`

**Current.**

```rust
pub async fn sign_out_and_wipe( &self, account_ref: String, ) -> Result<conversions::WipeOutcomeFfi, MarmotKitError>
```

Destructive sign-out: leave every active MLS group (best-effort), delete the account's relay-published KeyPackages, then wipe all local state for this account (MLS state DB, cached media/secrets, SQL account row, and the secret-store nsec). After this returns the account ref is no longer valid for any further FFI call. The returned `WipeOutcomeFfi` reports each stage independently so the app can show progress and a partial-failure sheet (mdk#478).

[Source](src/commands/account.rs#L72)

### `Marmot::sign_out`

**Current.**

```rust
pub async fn sign_out( &self, account_ref: String, delete_key_packages: bool, ) -> Result<conversions::SignOutOutcomeFfi, MarmotKitError>
```

Non-destructive sign-out: deactivate the account on this device and, when `delete_key_packages` is `true` (the default behavior in the UI), publish kind:5 deletions for its relay-published KeyPackages so strangers cannot gift-wrap a Welcome into a new group while it is signed out.

[Source](src/commands/account.rs#L95)

### `Marmot::create_identity`

**Current.**

```rust
pub async fn create_identity( &self, default_relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<AccountSummaryFfi, MarmotKitError>
```

Compatibility entry point for creating a brand-new Nostr identity. This retains the historical terminal-success contract: relay lists and the initial KeyPackage are published when it returns. New callers may use `create_identity_with_profile` for the earlier local-ready boundary and an explicit readiness state.

[Source](src/commands/account.rs#L111)

### `Marmot::create_identity_with_profile`

**Current.**

```rust
pub async fn create_identity_with_profile( &self, default_relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<IdentityCreationResultFfi, MarmotKitError>
```

Create a generated identity and return at durable local readiness with the exact locally persisted default profile. `readiness` remains the authority for whether relay publication has completed; `LocalReady` must not be presented as invite-receivable.

[Source](src/commands/account.rs#L140)

### `Marmot::account_setup_readiness`

**Current.**

```rust
pub fn account_setup_readiness( &self, account_ref: String, ) -> Result<AccountSetupReadinessFfi, MarmotKitError>
```

Read setup readiness without performing network I/O.

[Source](src/commands/account.rs#L173)

### `Marmot::login`

**Compatibility.** Prefer begin_onboarding for an interactive imported-account workflow.

```rust
pub async fn login( &self, identity: String, default_relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<AccountSummaryFfi, MarmotKitError>
```

Log in with an existing identity. `identity` can be an `nsec` (private key) for a local-signing account, or an `npub` to track a public identity without local signing.

[Source](src/commands/account.rs#L183)

### `Marmot::reset_incomplete_account_setup`

**Current.**

```rust
pub async fn reset_incomplete_account_setup( &self, nsec: String, acknowledge_possible_key_package_orphan: bool, ) -> Result<(), MarmotKitError>
```

Remove only the legacy ambiguous partial-account shape so a subsequent `login` with the same nsec can recreate it. The acknowledgement is required because old local state cannot prove that no KeyPackage was exposed before its stable slot was lost.

[Source](src/commands/account.rs#L218)

### `Marmot::login_recovering_incomplete_setup`

**Current.**

```rust
pub async fn login_recovering_incomplete_setup( &self, nsec: String, default_relays: Vec<String>, bootstrap_relays: Vec<String>, acknowledge_possible_key_package_orphan: bool, ) -> Result<AccountSummaryFfi, MarmotKitError>
```

Consent-gated one-call recovery for installations stranded before MDK had durable account-setup journals. This validates the same nsec, removes only the recognized ambiguous partial shape, preserves an existing account-id Keychain credential, and immediately retries login.

[Source](src/commands/account.rs#L234)

### `Marmot::login_external_signer`

**Compatibility.** Prefer begin_external_signer_onboarding for an interactive imported-account workflow. **C:** not exposed; external-signer callback vtable is not implemented.

```rust
pub async fn login_external_signer( &self, public_key: String, signer: std::sync::Arc<dyn ExternalAccountSignerFfi>, default_relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<AccountSummaryFfi, MarmotKitError>
```

Log in with an external account signer such as Amber/NIP-55.

[Source](src/commands/account.rs#L276)

### `Marmot::register_external_signer`

**Current.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
pub async fn register_external_signer( &self, account_ref: String, signer: std::sync::Arc<dyn ExternalAccountSignerFfi>, ) -> Result<(), MarmotKitError>
```

Re-register an external signer for an already-known external account.

[Source](src/commands/account.rs#L312)

### `Marmot::sign_in_account`

**Current.**

```rust
pub async fn sign_in_account( &self, account_ref: String, ) -> Result<AccountSummaryFfi, MarmotKitError>
```

Re-activate a non-destructively signed-out local account. This clears the durable signed-out marker and starts the account worker again; relay list/key-package repair can still be driven by the existing publish commands after sign-in.

[Source](src/commands/account.rs#L327)

### `Marmot::publish_relay_lists`

**Current.**

```rust
pub async fn publish_relay_lists( &self, account_ref: String, default_relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<(), MarmotKitError>
```

Publish (or re-publish) the NIP-65 and inbox relay lists for `account_ref`. Idempotent — safe to call on every launch.

[Source](src/commands/account.rs#L344)

### `Marmot::account_nip65_relays`

**Current.**

```rust
pub fn account_nip65_relays(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError>
```

Read the account NIP-65 relay list.

[Source](src/commands/account.rs#L360)

### `Marmot::account_inbox_relays`

**Current.**

```rust
pub fn account_inbox_relays(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError>
```

Read the account inbox relay list.

[Source](src/commands/account.rs#L364)

### `Marmot::account_key_packages`

**Compatibility.** Prefer local_account_key_packages then refresh_account_key_packages for settings UI.

```rust
pub async fn account_key_packages( &self, account_ref: String, bootstrap_relays: Vec<String>, ) -> Result<Vec<conversions::AccountKeyPackageFfi>, MarmotKitError>
```

List the local and relay-discovered Marmot KeyPackage publications for `account_ref`. Relay-backed rows are the current winner per addressable slot in the validated fetch window.

[Source](src/commands/account.rs#L371)

### `Marmot::local_account_key_packages`

**Current.**

```rust
pub fn local_account_key_packages( &self, account_ref: String, ) -> Result<Vec<conversions::AccountKeyPackageInventoryEntryFfi>, MarmotKitError>
```

Local-storage KeyPackage inventory with typed durable provenance. Does not wait for network startup or issue a directory query. Synchronous SQLCipher I/O on the calling thread; keep it off a UI or main thread.

[Source](src/commands/account.rs#L389)

### `Marmot::refresh_account_key_packages`

**Current.**

```rust
pub async fn refresh_account_key_packages( &self, account_ref: String, bootstrap_relays: Vec<String>, ) -> Result<Vec<conversions::AccountKeyPackageInventoryEntryFfi>, MarmotKitError>
```

Fetch validated relay observations, then merge a fresh local snapshot. Empty `bootstrap_relays` remains network-enabled. On failure, keep the previously rendered local result.

[Source](src/commands/account.rs#L404)

### `Marmot::account_key_package_relay_events`

**Current.**

```rust
pub async fn account_key_package_relay_events( &self, account_ref: String, bootstrap_relays: Vec<String>, ) -> Result<Vec<conversions::AccountKeyPackageRelayEventFfi>, MarmotKitError>
```

Observed relay history for `account_ref`: current and superseded kind-30443 events from one validated fetch window. Clients can pass a superseded event id and its source relays to the existing deletion API.

[Source](src/commands/account.rs#L421)

### `Marmot::publish_new_key_package`

**Current.**

```rust
pub async fn publish_new_key_package( &self, account_ref: String, ) -> Result<u64, MarmotKitError>
```

Publish a new fresh KeyPackage for `account_ref`.

[Source](src/commands/account.rs#L436)

### `Marmot::rotate_key_package`

**Current.**

```rust
pub async fn rotate_key_package(&self, account_ref: String) -> Result<u64, MarmotKitError>
```

Rotate the account's KeyPackage: mint and publish a fresh one, superseding the current slot. This is the sanctioned repair for an epoch-stalled group. `publish_new_key_package` is the same operation under its legacy name.

[Source](src/commands/account.rs#L447)

### `Marmot::republish_key_package`

**Current.**

```rust
pub async fn republish_key_package(&self, account_ref: String) -> Result<u64, MarmotKitError>
```

Re-publish the latest cached KeyPackage when possible, otherwise publish a fresh one.

[Source](src/commands/account.rs#L453)

### `Marmot::delete_account_key_package`

**Current.**

```rust
pub async fn delete_account_key_package( &self, account_ref: String, event_id_hex: String, relays: Vec<String>, ) -> Result<u64, MarmotKitError>
```

Publish a NIP-09 deletion for a KeyPackage event.

[Source](src/commands/account.rs#L458)

### `Marmot::set_account_nip65_relays`

**Current.**

```rust
pub async fn set_account_nip65_relays( &self, account_ref: String, relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError>
```

Publish the account read/write relay selection.

[Source](src/commands/account.rs#L470)

### `Marmot::set_account_inbox_relays`

**Current.**

```rust
pub async fn set_account_inbox_relays( &self, account_ref: String, relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError>
```

Publish the account inbox relay selection.

[Source](src/commands/account.rs#L487)

### `Marmot::account_follows`

**Current.**

```rust
pub fn account_follows(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError>
```

Return the complete locally cached kind-3 follow list for `account_ref` as canonical lowercase public-key hex strings.

[Source](src/commands/account.rs#L514)

### `Marmot::is_following`

**Current.**

```rust
pub fn is_following( &self, account_ref: String, user_ref: String, ) -> Result<bool, MarmotKitError>
```

Return whether `account_ref` currently follows `user_ref`, using the same local cache as `Self::account_follows`. `user_ref` accepts npub, hex, `nostr:npub…`, and Marmot profile links.

[Source](src/commands/account.rs#L521)

### `Marmot::follow_user`

**Current.**

```rust
pub async fn follow_user( &self, account_ref: String, user_ref: String, ) -> Result<Vec<String>, MarmotKitError>
```

Follow `user_ref` while preserving every other entry in the account's current kind-3 contact list. Returns the complete updated list.

[Source](src/commands/account.rs#L539)

### `Marmot::unfollow_user`

**Current.**

```rust
pub async fn unfollow_user( &self, account_ref: String, user_ref: String, ) -> Result<Vec<String>, MarmotKitError>
```

Unfollow `user_ref` while preserving every other entry in the account's current kind-3 contact list. Returns the complete updated list.

[Source](src/commands/account.rs#L553)

### `Marmot::reveal_nsec`

**Current.**

```rust
pub fn reveal_nsec(&self, account_ref: String) -> Result<String, MarmotKitError>
```

Export the active account's raw private key in canonical `nsec1...` bech32 form for an in-app key-backup display (mdk#543).

[Source](src/commands/account.rs#L577)

### `Marmot::export_encrypted_secret_key`

**Current.**

```rust
pub fn export_encrypted_secret_key( &self, account_ref: String, passphrase: String, ) -> Result<String, MarmotKitError>
```

Export the active account's private key as a password-encrypted NIP-49 `ncryptsec1...` bech32 backup string (mdk#544).

[Source](src/commands/account.rs#L594)

### `Marmot::publish_user_profile`

**Current.**

```rust
pub async fn publish_user_profile( &self, account_ref: String, profile: UserProfileMetadataFfi, default_relays: Vec<String>, bootstrap_relays: Vec<String>, ) -> Result<UserProfileMetadataFfi, MarmotKitError>
```

Publish Nostr kind:0 metadata with explicit caller-supplied relay overrides. Most app clients should use `publish_user_profile_using_account_relays`(Self::publish_user_profile_using_account_relays) so relay selection remains owned by MDK. This override remains for diagnostics, tests, and specialized clients.

[Source](src/commands/account.rs#L615)

### `Marmot::publish_user_profile_using_account_relays`

**Current.**

```rust
pub async fn publish_user_profile_using_account_relays( &self, account_ref: String, profile: UserProfileMetadataFfi, ) -> Result<UserProfileMetadataFfi, MarmotKitError>
```

Publish Nostr kind:0 metadata using one coherent snapshot of the selected account's MDK-owned relay configuration.

[Source](src/commands/account.rs#L642)

### `Marmot::upload_profile_image`

**Current.**

```rust
pub async fn upload_profile_image( &self, account_ref: String, data: Vec<u8>, media_type: String, blossom_server: Option<String>, ) -> Result<String, MarmotKitError>
```

Upload a public raster profile image to Blossom with the account's signer. The returned HTTPS URL can be published as kind:0 `picture`.

[Source](src/commands/account.rs#L659)

### `Marmot::download_profile_image`

**Compatibility.** Prefer avatar asset request/read for visible screen metadata.

```rust
pub async fn download_profile_image( &self, url: String, max_bytes: u64, ) -> Result<Vec<u8>, MarmotKitError>
```

Fetch one untrusted kind:0 profile `picture` URL with MDK dial-safe HTTPS policy, address pinning, and bounded streaming.

[Source](src/commands/account.rs#L674)

</details>

<details>
<summary>commands/agent_stream.rs</summary>

### `Marmot::start_agent_text_stream`

**Current.**

```rust
pub async fn start_agent_text_stream( &self, account_ref: String, group_id_hex: String, stream_id_hex: Option<String>, quic_candidates: Vec<String>, ) -> Result<AgentStreamStartFfi, MarmotKitError>
```

Anchor a live agent text stream start in the encrypted group history. Host apps pass the broker candidate(s) they will publish to, such as `quic://quic-broker.ipf.dev:4450`; omit `stream_id_hex` to let Rust generate a 32-byte stream id.

[Source](src/commands/agent_stream.rs#L50)

### `Marmot::watch_agent_text_stream`

**Current.**

```rust
pub async fn watch_agent_text_stream( &self, account_ref: String, group_id_hex: String, stream_id_hex: Option<String>, server_cert_der: Option<Vec<u8>>, insecure_local: bool, ) -> Result<Arc<AgentStreamSubscription>, MarmotKitError>
```

Watch a live agent text stream over the brokered QUIC channel. Pass `stream_id_hex = None` to follow the latest stream in the group (the common case when reacting to an AgentStreamStarted event). The returned subscription yields incremental `Chunk`s then a terminal `Finished` / `Failed`. `server_cert_der` pins a self-signed broker cert (else platform trust); `insecure_local` is loopback-only for testing.

[Source](src/commands/agent_stream.rs#L87)

</details>

<details>
<summary>commands/attachment_access.rs</summary>

### `Marmot::attachment_local_assets`

**Current.**

```rust
pub async fn attachment_local_assets( &self, account_ref: String, group_id_hex: String, targets: Vec<AttachmentLocalTargetFfi>, ) -> Result<Vec<AttachmentLocalAssetFfi>, MarmotKitError>
```

Local-only metadata for up to 64 original source slots in one group. Results preserve input order/duplicates. No bytes are loaded, jobs queued, downloads started or engine state hydrated. Requires no runtime start.

[Source](src/commands/attachment_access.rs#L12)

### `Marmot::read_attachment_asset`

**Current.**

```rust
pub async fn read_attachment_asset( &self, account_ref: String, reference: String, offset: u64, limit: u32, ) -> Result<AttachmentLocalBytesFfi, MarmotKitError>
```

Read 1..=1048576 bytes at an offset from an opaque local asset reference. Unavailable is distinct from available/empty EOF. Every call rechecks source visibility, expiry and account/store identity. No network fallback. Hosts own decoding and must discard assembled bytes if a chunk is unavailable.

[Source](src/commands/attachment_access.rs#L43)

</details>

<details>
<summary>commands/attachment_controls.rs</summary>

### `AttachmentTransferSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Result<Option<AttachmentTransferSnapshotFfi>, MarmotKitError>
```

Initial snapshot, then coalesced replacements. None means closed. Errors terminate this observation; close/drop never cancels acquisition.

[Source](src/commands/attachment_controls.rs#L12)

### `AttachmentTransferSubscription::cancel`

**Current.**

```rust
pub fn cancel(&self)
```

Stop observation and wake receivers; does not cancel acquisition.

[Source](src/commands/attachment_controls.rs#L21)

### `Marmot::attachment_download_policy`

**Current.**

```rust
pub async fn attachment_download_policy( &self, account_ref: String, ) -> Result<AttachmentDownloadPolicyFfi, MarmotKitError>
```

Read the durable per-account automatic acquisition, quota, disk-reserve and transfer-cap policy.

[Source](src/commands/attachment_controls.rs#L64)

### `Marmot::set_attachment_download_policy`

**Current.**

```rust
pub async fn set_attachment_download_policy( &self, account_ref: String, policy: AttachmentDownloadPolicyFfi, ) -> Result<(), MarmotKitError>
```

Validate and persist acquisition policy; disabling automatic work preserves explicit work and retained files.

[Source](src/commands/attachment_controls.rs#L74)

### `Marmot::control_attachment`

**Current.**

```rust
pub async fn control_attachment( &self, account_ref: String, reference: String, control: AttachmentControlFfi, ) -> Result<bool, MarmotKitError>
```

Cancel durably, retry explicitly, or remove local bytes. Returns false for obsolete references or ineligible operations; cancellation preserves ready bytes.

[Source](src/commands/attachment_controls.rs#L86)

### `Marmot::download_attachment_again`

**Current.**

```rust
pub async fn download_attachment_again( &self, account_ref: String, group_id_hex: String, target: AttachmentLocalTargetFfi, ) -> Result<Option<String>, MarmotKitError>
```

Queue explicit acquisition for a current original source slot, clearing removal/cancellation; no reference means unavailable or obsolete.

[Source](src/commands/attachment_controls.rs#L98)

### `Marmot::attachment_transfer_snapshot`

**Current.**

```rust
pub async fn attachment_transfer_snapshot( &self, account_ref: String, group_id_hex: String, targets: Vec<AttachmentLocalTargetFfi>, ) -> Result<AttachmentTransferSnapshotFfi, MarmotKitError>
```

Read bounded transfer state for up to 64 source slots in one group without requesting a transfer.

[Source](src/commands/attachment_controls.rs#L111)

### `Marmot::subscribe_attachment_transfers`

**Current.**

```rust
pub async fn subscribe_attachment_transfers( &self, account_ref: String, group_id_hex: String, targets: Vec<AttachmentLocalTargetFfi>, ) -> Result<Arc<AttachmentTransferSubscription>, MarmotKitError>
```

Observe initial transfer state and coalesced complete replacements for bounded source slots; observation does not request a transfer.

[Source](src/commands/attachment_controls.rs#L133)

</details>

<details>
<summary>commands/attachment_history.rs</summary>

### `Marmot::attachment_history_page`

**Current.**

```rust
pub async fn attachment_history_page( &self, account_ref: String, group_id_hex: String, limit: u32, cursor: Option<Arc<AttachmentHistoryCursor>>, ) -> Result<AttachmentPageReadFfi, MarmotKitError>
```

Read 1..=100 attachment slots in canonical newest-first order. Rejected slots consume the limit. Filter categories within returned pages; an empty filtered page is not exhaustion while has_more is true. No downloads are started. Keep cursors/versions in memory only and restart after runtime reconstruction.

[Source](src/commands/attachment_history.rs#L14)

### `Marmot::attachment_history_version`

**Current.**

```rust
pub async fn attachment_history_version( &self, account_ref: String, group_id_hex: String, ) -> Result<Arc<AttachmentHistoryVersion>, MarmotKitError>
```

Cheap local refresh signal, including for a fully loaded or empty library. Compare against the baseline version captured when the current collection began: replacing that baseline with a newer page can hide a destructive change to earlier rows.

[Source](src/commands/attachment_history.rs#L36)

</details>

<details>
<summary>commands/audit.rs</summary>

### `Marmot::audit_log_settings`

**Current.**

```rust
pub fn audit_log_settings(&self) -> Result<AuditLogSettingsFfi, MarmotKitError>
```

Local forensic audit-log recording settings. Recording is opt-in and only applies to account sessions opened after the setting is enabled.

[Source](src/commands/audit.rs#L14)

### `Marmot::set_audit_log_settings`

**Current.**

```rust
pub async fn set_audit_log_settings( &self, settings: AuditLogSettingsFfi, ) -> Result<AuditLogSettingsFfi, MarmotKitError>
```

Persist local forensic audit-log recording settings and return the stored value.

[Source](src/commands/audit.rs#L24)

### `Marmot::set_audit_log_tracker_config`

**Current.**

```rust
pub fn set_audit_log_tracker_config( &self, config: AuditLogTrackerConfigV4Ffi, ) -> Result<AuditLogTrackerConfigV4Ffi, MarmotKitError>
```

Supply non-persisted audit tracker upload metadata: optional Goggles upload URL override, bearer token from the host app, and optional system hardware model, platform, and app version.

[Source](src/commands/audit.rs#L41)

### `Marmot::audit_log_files`

**Current.**

```rust
pub fn audit_log_files(&self) -> Result<Vec<AuditLogFileFfi>, MarmotKitError>
```

Local JSONL audit logs available for explicit forensic upload.

[Source](src/commands/audit.rs#L51)

### `Marmot::post_audit_log_file`

**Current.**

```rust
pub async fn post_audit_log_file( &self, path: String, endpoint: String, ) -> Result<AuditLogUploadResultFfi, MarmotKitError>
```

POST one selected JSONL audit log to a forensic analyzer endpoint.

[Source](src/commands/audit.rs#L61)

### `Marmot::delete_audit_log_file`

**Current.**

```rust
pub async fn delete_audit_log_file( &self, path: String, ) -> Result<AuditLogDeleteResultFfi, MarmotKitError>
```

Delete one local JSONL audit log file (e.g. behind a "clear audit log" button).

[Source](src/commands/audit.rs#L81)

### `Marmot::post_audit_log_tracker_update`

**Current.**

```rust
pub async fn post_audit_log_tracker_update( &self, ) -> Result<AuditLogTrackerUpdateResultFfi, MarmotKitError>
```

POST all local audit logs to the configured tracker when audit logging is enabled. This is safe for host apps to call unconditionally; disabled or unconfigured states return a structured skip result.

[Source](src/commands/audit.rs#L91)

</details>

<details>
<summary>commands/avatar.rs</summary>

### `Marmot::request_avatar_assets`

**Current.**

```rust
pub async fn request_avatar_assets( &self, account_ref: String, targets: Vec<String>, ) -> Result<Vec<AvatarAssetFfi>, MarmotKitError>
```

Pass up to 16 opaque targets from visible screen metadata. Does not await HTTP.

[Source](src/commands/avatar.rs#L16)

### `Marmot::read_avatar_assets`

**Current.**

```rust
pub async fn read_avatar_assets( &self, account_ref: String, references: Vec<String>, max_bytes: u64, ) -> Result<Vec<AvatarBytesFfi>, MarmotKitError>
```

Local-only read, up to 16 references and a 1-byte..16-MiB aggregate byte budget. Results preserve input order; deferred entries can be retried in a later batch.

[Source](src/commands/avatar.rs#L37)

### `Marmot::clear_avatar_cache`

**Current.**

```rust
pub async fn clear_avatar_cache(&self, account_ref: String) -> Result<(), MarmotKitError>
```

Clear durable avatar bytes and demand; later visible requests can acquire again.

[Source](src/commands/avatar.rs#L57)

</details>

<details>
<summary>commands/chat_list.rs</summary>

### `Marmot::chat_list`

**Lower-level.** Raw full list; prepared bounded screens use open_chat_list_window.

```rust
pub fn chat_list( &self, account_ref: String, include_archived: bool, ) -> Result<Vec<ChatListRowFfi>, MarmotKitError>
```

Durable chat-list rows for fast app launch. Rows include the group title/avatar, last kind-9 preview, unread count, and read anchors.

[Source](src/commands/chat_list.rs#L16)

### `Marmot::chat_list_row`

**Lower-level.** Raw keyed row; selected presentation uses presented_chat_list_row.

```rust
pub fn chat_list_row( &self, account_ref: String, group_id_hex: String, ) -> Result<Option<ChatListRowFfi>, MarmotKitError>
```

Read one hydrated chat-list row for a known group.

[Source](src/commands/chat_list.rs#L39)

### `Marmot::existing_direct_conversation`

**Current.**

```rust
pub async fn existing_direct_conversation( &self, account_ref: String, peer_account_id: String, ) -> Result<Option<ExistingDirectConversationFfi>, MarmotKitError>
```

Look up the reusable existing direct conversation with `peer_account_id`.

[Source](src/commands/chat_list.rs#L80)

### `Marmot::initialize_chat_read_state`

**Current.**

```rust
pub fn initialize_chat_read_state( &self, account_ref: String, group_id_hex: String, ) -> Result<Option<ChatListRowFfi>, MarmotKitError>
```

Establish the unread baseline the first time a user opens a group. Existing kind-9 history remains read; later remote kind-9 messages count until marked visible via `mark_timeline_message_read`.

[Source](src/commands/chat_list.rs#L106)

### `Marmot::mark_timeline_message_read`

**Current.**

```rust
pub fn mark_timeline_message_read( &self, account_ref: String, group_id_hex: String, message_id_hex: String, ) -> Result<Option<ChatListRowFfi>, MarmotKitError>
```

Mark a kind-9 timeline message visible/read. Own kind-9 messages can advance the marker too, which clears any earlier unread messages.

[Source](src/commands/chat_list.rs#L120)

### `Marmot::set_chat_manually_unread`

**Current.**

```rust
pub fn set_chat_manually_unread( &self, account_ref: String, group_id_hex: String, manually_unread: bool, ) -> Result<Option<ChatListRowFfi>, MarmotKitError>
```

Set or clear a manual unread reminder without moving the durable timeline read marker backwards.

[Source](src/commands/chat_list.rs#L140)

### `Marmot::set_chat_pinned`

**Current.**

```rust
pub fn set_chat_pinned( &self, account_ref: String, group_id_hex: String, pinned: bool, ) -> Result<ChatPinStateFfi, MarmotKitError>
```

Pin or unpin one local chat. Newly pinned chats enter at the top of the manually ordered pinned section.

[Source](src/commands/chat_list.rs#L155)

### `Marmot::set_pinned_chat_order`

**Current.**

```rust
pub fn set_pinned_chat_order( &self, account_ref: String, ordered_group_ids: Vec<String>, ) -> Result<ChatPinStateFfi, MarmotKitError>
```

Atomically replace the order of the current pinned set. The input must contain every currently pinned group exactly once.

[Source](src/commands/chat_list.rs#L170)

### `Marmot::chat_notification_settings`

**Current.**

```rust
pub fn chat_notification_settings( &self, account_ref: String, group_id_hex: String, ) -> Result<ChatNotificationSettingsFfi, MarmotKitError>
```

Read the current MDK timed/indefinite mute state for one chat.

[Source](src/commands/chat_list.rs#L188)

### `Marmot::set_chat_muted`

**Current.**

```rust
pub fn set_chat_muted( &self, account_ref: String, group_id_hex: String, muted_until_ms: Option<i64>, ) -> Result<ChatNotificationSettingsFfi, MarmotKitError>
```

Mute one chat until an absolute Unix epoch millisecond timestamp, or indefinitely when `muted_until_ms` is `None`.

[Source](src/commands/chat_list.rs#L202)

### `Marmot::clear_chat_muted`

**Current.**

```rust
pub fn clear_chat_muted( &self, account_ref: String, group_id_hex: String, ) -> Result<ChatNotificationSettingsFfi, MarmotKitError>
```

Clear either a finite or indefinite MDK chat mute.

[Source](src/commands/chat_list.rs#L216)

</details>

<details>
<summary>commands/chat_window.rs</summary>

### `Marmot::open_chat_list_window`

**Current.**

```rust
pub async fn open_chat_list_window( &self, account_ref: String, view: ChatListViewFfi, initial_rows: Option<u32>, ) -> Result<Arc<ChatListWindowSubscription>, MarmotKitError>
```

Bind to one account/view. None defaults to 50; explicit sizes must be 1–100.

[Source](src/commands/chat_window.rs#L9)

### `Marmot::subscribe_account_attention`

**Current.**

```rust
pub async fn subscribe_account_attention( &self, ) -> Result<Arc<AccountAttentionSubscription>, MarmotKitError>
```

Signed-in local/external accounts, independent of any list or active worker.

[Source](src/commands/chat_window.rs#L22)

</details>

<details>
<summary>commands/conversation_window.rs</summary>

### `Marmot::open_conversation_window`

**Current.**

```rust
pub async fn open_conversation_window( &self, account_ref: String, group_id_hex: String, mode: ConversationOpenModeFfi, message_id_hex: Option<String>, initial_rows: Option<u32>, timeout_ms: u32, ) -> Result<Arc<ConversationWindowSubscription>, MarmotKitError>
```

Open first unread/latest or an explicit message. No implicit mark-read. Zero timeout uses 30 seconds; timeout/cancellation abandons the opening. Mode Message requires a message id; other modes reject one. None rows uses 50.

[Source](src/commands/conversation_window.rs#L11)

### `Marmot::send_message_draft`

**Current.**

```rust
pub async fn send_message_draft( &self, account_ref: String, revision: Arc<MessageDraftRevisionFfi>, attachments: Vec<MediaAttachmentReferenceFfi>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Submit exactly the selected draft revision. Prepared media must match its descriptors. Clears only on durable acceptance; do not clear again in the host after delivery.

[Source](src/commands/conversation_window.rs#L52)

### `Marmot::selected_message_draft`

**Current.**

```rust
pub fn selected_message_draft( &self, account_ref: String, group_id_hex: String, ) -> Result<SelectedMessageDraftFfi, MarmotKitError>
```

Descriptor-only selected draft with an opaque store/group-scoped revision.

[Source](src/commands/conversation_window.rs#L71)

### `Marmot::clear_message_draft_if_revision`

**Current.**

```rust
pub fn clear_message_draft_if_revision( &self, account_ref: String, revision: Arc<MessageDraftRevisionFfi>, ) -> Result<SelectedMessageDraftFfi, MarmotKitError>
```

Clear only the exact revision the caller observed; handle conflict instead of erasing a newer draft.

[Source](src/commands/conversation_window.rs#L82)

### `Marmot::save_message_draft_if_revision`

**Current.**

```rust
pub fn save_message_draft_if_revision( &self, account_ref: String, revision: Arc<MessageDraftRevisionFfi>, content: String, reply_to_message_id_hex: Option<String>, media_attachments: Vec<MessageDraftAttachmentFfi>, ) -> Result<SelectedMessageDraftFfi, MarmotKitError>
```

Save composer state conditional on the observed revision; use the returned result/revision for subsequent edits.

[Source](src/commands/conversation_window.rs#L92)

### `Marmot::message_draft_attachment_if_revision`

**Current.**

```rust
pub fn message_draft_attachment_if_revision( &self, account_ref: String, revision: Arc<MessageDraftRevisionFfi>, attachment_id: String, ) -> Result<Option<Vec<u8>>, MarmotKitError>
```

Read only the requested local attachment, rejecting a changed selected draft.

[Source](src/commands/conversation_window.rs#L113)

</details>

<details>
<summary>commands/directory.rs</summary>

### `Marmot::display_name`

**Current.**

```rust
pub fn display_name(&self, account_id_hex: String) -> Option<String>
```

Best-effort cached display name for an account id. Returns the Nostr kind:0 display_name/name when the runtime has projected one, or the local account label if the id refers to one of our own accounts. `None` when nothing is known yet — call `refresh_profile` to fetch.

[Source](src/commands/directory.rs#L21)

### `Marmot::npub`

**Current.**

```rust
pub fn npub(&self, account_id_hex: String) -> Option<String>
```

Convert a hex account id (Nostr public key) into its `npub…` bech32 form for display. `None` if the hex isn't a valid public key.

[Source](src/commands/directory.rs#L27)

### `Marmot::account_id_hex`

**Current.**

```rust
pub fn account_id_hex(&self, reference: String) -> Option<String>
```

Normalize a public-key reference (hex, `npub`, `nostr:npub`, `nprofile`, `nostr:nprofile`, or a `marmot://profile/` link) to canonical hex. `None` if it isn't a valid public identity reference. nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, the nprofile fallback rejects encoded tokens longer than 1023 UTF-8 bytes; a valid 1023-byte token still decodes when wrapped. Used to resolve a scanned or deep-linked mention back to the account id the rest of the API expects.

[Source](src/commands/directory.rs#L40)

### `Marmot::default_profile_pseudonym`

**Current.**

```rust
pub fn default_profile_pseudonym(&self, account_id_hex: String) -> String
```

Deterministic cosmetic display name for a canonical hex account id.

[Source](src/commands/directory.rs#L51)

### `Marmot::random_profile_pseudonym`

**Current.**

```rust
pub fn random_profile_pseudonym(&self) -> String
```

Random cosmetic display name from the shared wordlists.

[Source](src/commands/directory.rs#L59)

### `Marmot::parse_markdown`

**Current.**

```rust
pub fn parse_markdown(&self, text: String) -> MarkdownDocumentFfi
```

Parse plaintext message content into the same Markdown AST returned on message and timeline records. Useful for draft previews and host-side fallback rendering.

[Source](src/commands/directory.rs#L66)

### `Marmot::user_profile`

**Current.**

```rust
pub fn user_profile( &self, account_id_hex: String, ) -> Result<Option<UserProfileMetadataFfi>, MarmotKitError>
```

Full cached Nostr kind:0 profile for an account id (name, display name, about, picture, nip05, lud16), if the runtime has one projected. The local account's own profile is cached immediately after `publish_user_profile`; other accounts' profiles populate via `refresh_profile`. Returns `None` when nothing is cached yet.

[Source](src/commands/directory.rs#L75)

### `Marmot::cached_identity_projections`

**Current.**

```rust
pub fn cached_identity_projections( &self, account_id_hexes: Vec<String>, ) -> Result<Vec<CachedIdentityProjectionFfi>, MarmotKitError>
```

Bounded local cached-identity page for many account IDs.

[Source](src/commands/directory.rs#L91)

### `Marmot::user_profile_website`

**Current.**

```rust
pub fn user_profile_website( &self, account_id_hex: String, ) -> Result<Option<String>, MarmotKitError>
```

Cached Nostr kind:0 `website` metadata for an account id, when it is a string. The generic profile record intentionally exposes the fields the host can publish; this read-only accessor preserves arbitrary kind:0 metadata while still making the standard website field available to profile presentation surfaces.

[Source](src/commands/directory.rs#L113)

### `Marmot::refresh_profile`

**Current.**

```rust
pub async fn refresh_profile( &self, account_id_hex: String, relays: Vec<String>, ) -> Result<(), MarmotKitError>
```

Fetch and cache an account's own Nostr kind:0 profile from `relays`. After this resolves, `user_profile` / `display_name` return the freshly-fetched metadata (name, picture, etc.) for that account.

[Source](src/commands/directory.rs#L130)

### `Marmot::user_relay_lists`

**Current.**

```rust
pub fn user_relay_lists( &self, account_id_hex: String, ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError>
```

Cached NIP-65 and inbox relay lists for any account id — no network. An account with nothing cached yet returns an empty status with both kinds in `missing` rather than erroring; call `refresh_user_relay_lists` to fetch.

[Source](src/commands/directory.rs#L145)

### `Marmot::refresh_user_relay_lists`

**Current.**

```rust
pub async fn refresh_user_relay_lists( &self, account_id_hex: String, relays: Vec<String>, ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError>
```

Fetch an account's published NIP-65 and inbox relay lists from `relays`, updating the cache. An account with nothing published reports both kinds in `missing` rather than erroring.

[Source](src/commands/directory.rs#L158)

### `Marmot::search_cached_users`

**Current.**

```rust
pub fn search_cached_users( &self, account_id_hex: String, query: String, limit: u32, ) -> Result<Vec<conversions::UserDirectorySearchResultFfi>, MarmotKitError>
```

Search public identities cached through any connected account, without network or group-membership work. Follow flags refer only to the selected searcher. Call off the UI thread; zero limit returns no rows.

[Source](src/commands/directory.rs#L173)

### `Marmot::search_users`

**Current.**

```rust
pub async fn search_users( &self, account_id_hex: String, query: String, radius_start: u8, radius_end: u8, ) -> Result<Arc<UserSearchSubscription>, MarmotKitError>
```

Stream cached public identities across accounts, then independent provider and graph results. The radius window bounds known social distances; cached/provider identities without a known distance remain discoverable. Those identities can recur when paging radii: deduplicate by account id across pages as well as within each subscription.

[Source](src/commands/directory.rs#L199)

</details>

<details>
<summary>commands/draft.rs</summary>

### `Marmot::message_drafts`

**Current.**

```rust
pub fn message_drafts( &self, account_ref: String, ) -> Result<Vec<MessageDraftSummaryFfi>, MarmotKitError>
```

Metadata-only saved composer drafts for an account, newest-updated first. Attachment plaintext is intentionally omitted from this list; call `messageDraft` when restoring one selected composer. Hosts must delete empty or sent drafts; deleting a group also removes its draft.

[Source](src/commands/draft.rs#L15)

### `Marmot::message_draft`

**Compatibility.** Prefer selected_message_draft for the revisioned composer.

```rust
pub fn message_draft( &self, account_ref: String, group_id_hex: String, ) -> Result<Option<MessageDraftFfi>, MarmotKitError>
```

The saved composer draft for an account and MLS group, if one exists.

[Source](src/commands/draft.rs#L28)

### `Marmot::save_message_draft`

**Compatibility.** Prefer save_message_draft_if_revision for concurrent composer safety.

```rust
pub fn save_message_draft( &self, account_ref: String, group_id_hex: String, content: String, reply_to_message_id_hex: Option<String>, media_attachments: Vec<MessageDraftAttachmentFfi>, ) -> Result<MessageDraftFfi, MarmotKitError>
```

Upsert a composer draft into the account's encrypted SQLCipher store.

[Source](src/commands/draft.rs#L41)

### `Marmot::delete_message_draft`

**Compatibility.** Prefer clear_message_draft_if_revision for concurrent composer safety.

```rust
pub fn delete_message_draft( &self, account_ref: String, group_id_hex: String, ) -> Result<(), MarmotKitError>
```

Delete a saved composer draft. This is a no-op when no draft exists.

[Source](src/commands/draft.rs#L64)

</details>

<details>
<summary>commands/group.rs</summary>

### `Marmot::prewarm_group_member_key_packages`

**Current.**

```rust
pub async fn prewarm_group_member_key_packages( &self, account_ref: String, member_refs: Vec<String>, ) -> Result<MemberKeyPackagePrewarmSummaryFfi, MarmotKitError>
```

Resolve the current composition roster before Create is tapped. The result is aggregate-only; no package is reserved or consumed, and the later create call revalidates cached packages before MLS mutation.

[Source](src/commands/group.rs#L393)

### `Marmot::create_group`

**Current.**

```rust
pub async fn create_group( &self, account_ref: String, name: String, member_refs: Vec<String>, description: Option<String>, ) -> Result<String, MarmotKitError>
```

Create a new MLS group with `name` and the given members. Members are referenced by `npub` or hex account id. Returns the locally canonical group id as hex; this confirms local canonicalization, not Welcome delivery. `WelcomeDeliveryPending` is a delivery-failure signal, not an acknowledgement. Hosts should subscribe before creation and/or query `pending_welcome_deliveries` afterward before presenting invitation success.

[Source](src/commands/group.rs#L412)

### `Marmot::create_group_with_options`

**Current.**

```rust
pub async fn create_group_with_options( &self, account_ref: String, name: String, member_refs: Vec<String>, options: CreateGroupOptionsFfi, ) -> Result<String, MarmotKitError>
```

Create a group with forward-compatible founding options. A nonzero retention value is written into the founding MLS state and Welcome; it does not emit a follow-up retention commit or publication.

[Source](src/commands/group.rs#L429)

### `Marmot::create_group_detailed`

**Current.**

```rust
pub async fn create_group_detailed( &self, account_ref: String, name: String, member_refs: Vec<String>, description: Option<String>, ) -> Result<CreatedGroupFfi, MarmotKitError>
```

Create a group and return the exact durable chat-list row available to subscriptions and queries at the response boundary.

[Source](src/commands/group.rs#L445)

### `Marmot::create_group_with_options_detailed`

**Current.**

```rust
pub async fn create_group_with_options_detailed( &self, account_ref: String, name: String, member_refs: Vec<String>, options: CreateGroupOptionsFfi, ) -> Result<CreatedGroupFfi, MarmotKitError>
```

Create a group with forward-compatible founding options and return the exact durable chat-list row available at the response boundary.

[Source](src/commands/group.rs#L461)

### `Marmot::create_group_with_initial_image`

**Current.**

```rust
pub async fn create_group_with_initial_image( &self, account_ref: String, name: String, member_refs: Vec<String>, description: Option<String>, initial_image: Option<InitialGroupImageFfi>, ) -> Result<String, MarmotKitError>
```

Create a group with an optional initial avatar. MDK prefers an encrypted Blossom image and uses `source_url` only when the founding members do not all support that component but do support URL avatars.

[Source](src/commands/group.rs#L478)

### `Marmot::stage_prepared_group_image`

**Current.**

```rust
pub async fn stage_prepared_group_image( &self, account_ref: String, plaintext: Vec<u8>, media_type: String, ) -> Result<PreparedGroupImageUploadFfi, MarmotKitError>
```

Validate and durably encrypt a founding image without performing any network transfer. The opaque id survives process restart; keys, ciphertext, and the content hash stay inside MDK's SQLCipher database.

[Source](src/commands/group.rs#L503)

### `Marmot::upload_prepared_group_image`

**Current.**

```rust
pub async fn upload_prepared_group_image( &self, account_ref: String, upload_id: String, ) -> Result<PreparedGroupImageUploadFfi, MarmotKitError>
```

Upload a staged founding image. A transfer failure is returned as an error after its failed status is durably recorded, and can be retried with the same id; an already uploaded id performs no duplicate HTTP transfer.

[Source](src/commands/group.rs#L521)

### `Marmot::prepared_group_image_status`

**Current.**

```rust
pub async fn prepared_group_image_status( &self, account_ref: String, upload_id: String, ) -> Result<PreparedGroupImageUploadFfi, MarmotKitError>
```

Read one prepared group-image operation status.

[Source](src/commands/group.rs#L533)

### `Marmot::prepared_group_images`

**Current.**

```rust
pub async fn prepared_group_images( &self, account_ref: String, ) -> Result<Vec<PreparedGroupImageUploadFfi>, MarmotKitError>
```

List prepared group-image operations.

[Source](src/commands/group.rs#L545)

### `Marmot::create_group_with_prepared_initial_image`

**Current.**

```rust
pub async fn create_group_with_prepared_initial_image( &self, account_ref: String, name: String, member_refs: Vec<String>, description: Option<String>, upload_id: String, ) -> Result<String, MarmotKitError>
```

Fast founding-image create path. `upload_id` must already be uploaded; the image component is present in epoch-zero metadata and no Blossom request occurs on this call. Reusing a consumed id returns its original canonical group rather than creating a duplicate.

[Source](src/commands/group.rs#L562)

### `Marmot::create_group_with_initial_image_detailed`

**Current.**

```rust
pub async fn create_group_with_initial_image_detailed( &self, account_ref: String, name: String, member_refs: Vec<String>, description: Option<String>, initial_image: Option<InitialGroupImageFfi>, ) -> Result<CreatedGroupFfi, MarmotKitError>
```

Create a group with an initial image and detailed operation outcome.

[Source](src/commands/group.rs#L583)

### `Marmot::normalize_member_ref`

**Current.**

```rust
pub fn normalize_member_ref(&self, member_ref: String) -> Result<MemberRefFfi, MarmotKitError>
```

Normalize a member reference for group-management UI. Accepts hex, `npub`, `nostr:npub...`, `nprofile`, `nostr:nprofile...`, and `marmot://profile/...` references. nprofile relay hints are discarded and never used for routing or membership authorization. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, the nprofile fallback rejects encoded tokens longer than 1023 UTF-8 bytes; a valid 1023-byte token still decodes when wrapped.

[Source](src/commands/group.rs#L613)

### `Marmot::group_members`

**Current.**

```rust
pub async fn group_members( &self, account_ref: String, group_id_hex: String, ) -> Result<Vec<AppGroupMemberRecordFfi>, MarmotKitError>
```

Membership roster for `group_id_hex`.

[Source](src/commands/group.rs#L618)

### `Marmot::group_member_ids_page`

**Current.**

```rust
pub async fn group_member_ids_page( &self, account_ref: String, group_ids_hex: Vec<String>, ) -> Result<Vec<AppGroupMemberIdsFfi>, MarmotKitError>
```

Identifier-only rosters for a bounded page of groups.

[Source](src/commands/group.rs#L635)

### `Marmot::group_details`

**Current.**

```rust
pub async fn group_details( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupDetailsFfi, MarmotKitError>
```

Group plus enriched member rows for detail screens.

[Source](src/commands/group.rs#L659)

### `Marmot::group_conversation_snapshot`

**Current.**

```rust
pub async fn group_conversation_snapshot( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupConversationSnapshotFfi, MarmotKitError>
```

Group details and management state captured for conversation loading in one worker command. The authoritative group record, roster, and MLS state share one session/snapshot frontier; management state is derived from those exact returned details without another await.

[Source](src/commands/group.rs#L672)

### `Marmot::group_roster`

**Current.**

```rust
pub async fn group_roster( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupRosterFfi, MarmotKitError>
```

Lightweight membership roster projection for membership screens.

[Source](src/commands/group.rs#L682)

### `Marmot::group_management_state`

**Current.**

```rust
pub async fn group_management_state( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupManagementStateFfi, MarmotKitError>
```

Current caller permissions plus per-member action availability.

[Source](src/commands/group.rs#L693)

### `Marmot::enable_group_disbanding`

**Current.**

```rust
pub async fn enable_group_disbanding( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Install lifecycle-v1 and require it in one admin Commit.

[Source](src/commands/group.rs#L704)

### `Marmot::disband_group`

**Current.**

```rust
pub async fn disband_group( &self, account_ref: String, group_id_hex: String, ) -> Result<DisbandRequestFfi, MarmotKitError>
```

Durably accept an irreversible disband request. Completion is observed through normal group state updates after bounded convergence.

[Source](src/commands/group.rs#L724)

### `Marmot::acknowledge_disband_failure`

**Current.**

```rust
pub async fn acknowledge_disband_failure( &self, account_ref: String, group_id_hex: String, ) -> Result<bool, MarmotKitError>
```

Acknowledge the recorded group-disband failure.

[Source](src/commands/group.rs#L738)

### `Marmot::invite_members`

**Current.**

```rust
pub async fn invite_members( &self, account_ref: String, group_id_hex: String, member_refs: Vec<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Invite `member_refs` into an existing group.

[Source](src/commands/group.rs#L751)

### `Marmot::invite_members_with_initial_admins`

**Current.**

```rust
pub async fn invite_members_with_initial_admins( &self, account_ref: String, group_id_hex: String, member_refs: Vec<String>, initial_admin_refs: Vec<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Invite `member_refs` and grant admin to `initial_admin_refs` in the same invite commit. Each initial admin must be one of the invitees.

[Source](src/commands/group.rs#L763)

### `Marmot::remove_members`

**Current.**

```rust
pub async fn remove_members( &self, account_ref: String, group_id_hex: String, member_refs: Vec<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Request removal of selected members; use the detailed variant for operation outcomes.

[Source](src/commands/group.rs#L787)

### `Marmot::leave_group`

**Current.**

```rust
pub async fn leave_group( &self, account_ref: String, group_id_hex: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Queue leaving a group; retained local history is separate from membership.

[Source](src/commands/group.rs#L805)

### `Marmot::forget_group_local`

**Current.**

```rust
pub async fn forget_group_local( &self, account_ref: String, group_id_hex: String, ) -> Result<bool, MarmotKitError>
```

Reset a group on this account-device, without sending an MLS leave or disband. Erases local history and protocol state, cancels group work, and rejects old welcomes. A valid Welcome whose authenticated inner creation time is strictly newer than the reset's Unix-second cutoff can join the same group with fresh state. Equal-second invitations are rejected; receipt time and outer wrapper time do not establish freshness. Hosts should close the group's UI subscriptions and clear their media caches. Returns true when resetting, false when already awaiting a fresh Welcome.

[Source](src/commands/group.rs#L827)

### `Marmot::delete_group_local`

**Current.**

```rust
pub async fn delete_group_local( &self, account_ref: String, group_id_hex: String, ) -> Result<bool, MarmotKitError>
```

Delete this group's local app data without performing an MLS leave. The caller should cancel any active UI subscriptions for the group before invoking the wipe. The runtime removes the active transport route, then transactionally drops the chat-list/account projection, plaintext app events, timeline rows, agent-stream projection rows, push-token rows, and cached encrypted-media epoch secrets. MLS/OpenMLS group state is left intact; a future fresh group delivery can recreate a local chat row. Returns true if any local rows or a live route were removed.

[Source](src/commands/group.rs#L847)

### `Marmot::update_message_retention`

**Current.**

```rust
pub async fn update_message_retention( &self, account_ref: String, group_id_hex: String, disappearing_message_secs: u64, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Set the per-group disappearing-message retention, wrapping the engine's `update_message_retention`. `disappearing_message_secs` of `0` disables expiry; any positive value is the retention window in seconds. Thin passthrough over the already-public engine API (mdk#571).

[Source](src/commands/group.rs#L863)

### `Marmot::group_recovery_status`

**Current.**

```rust
pub async fn group_recovery_status( &self, account_ref: String, group_id_hex: String, ) -> Result<crate::conversions::GroupRecoveryStatusFfi, MarmotKitError>
```

Re-read on GroupStateUpdated; display uncertainty separately from whether the user accepted the original invitation.

[Source](src/commands/group.rs#L879)

### `Marmot::confirm_group_rejoin`

**Current.**

```rust
pub async fn confirm_group_rejoin( &self, account_ref: String, welcome_id_hex: String, local_state_token: String, ) -> Result<crate::conversions::GroupRecoveryStatusFfi, MarmotKitError>
```

Call only after explicit user consent to replace the active copy. Show the offer's authenticated inviter and pass its exact id and state token.

[Source](src/commands/group.rs#L894)

### `Marmot::decline_group_rejoin`

**Current.**

```rust
pub async fn decline_group_rejoin( &self, account_ref: String, welcome_id_hex: String, ) -> Result<(), MarmotKitError>
```

Decline a proposed recovery rejoin.

[Source](src/commands/group.rs#L909)

### `Marmot::accept_group_invite`

**Current.**

```rust
pub async fn accept_group_invite( &self, account_ref: String, group_id_hex: String, ) -> Result<AppGroupRecordFfi, MarmotKitError>
```

Accept a pending group invitation.

[Source](src/commands/group.rs#L921)

### `Marmot::decline_group_invite`

**Current.**

```rust
pub async fn decline_group_invite( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupInviteDeclineResultFfi, MarmotKitError>
```

Decline a pending group invitation.

[Source](src/commands/group.rs#L934)

### `Marmot::update_group_profile`

**Current.**

```rust
pub async fn update_group_profile( &self, account_ref: String, group_id_hex: String, name: Option<String>, description: Option<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Update the group name and description.

[Source](src/commands/group.rs#L947)

### `Marmot::update_group_image`

**Current.**

```rust
pub async fn update_group_image( &self, account_ref: String, group_id_hex: String, plaintext: Vec<u8>, media_type: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Encrypt and upload a group avatar to Blossom, then commit the `marmot.group.blossom.image.v1` component. `plaintext` must contain the decoded image bytes; use `clear_group_image` to remove an existing encrypted Blossom avatar.

[Source](src/commands/group.rs#L966)

### `Marmot::clear_group_image`

**Current.**

```rust
pub async fn clear_group_image( &self, account_ref: String, group_id_hex: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Clear the group's encrypted Blossom avatar by committing the absent `marmot.group.blossom.image.v1` component state.

[Source](src/commands/group.rs#L984)

### `Marmot::download_group_blossom_image`

**Compatibility.** Prefer avatar asset request/read for visible screen metadata.

```rust
pub async fn download_group_blossom_image( &self, account_ref: String, group_id_hex: String, ) -> Result<Vec<u8>, MarmotKitError>
```

Fetch and decrypt the group's encrypted Blossom avatar (`marmot.group.blossom.image.v1`) into raw image bytes (PNG/JPEG/…). Errors when the group has no Blossom image set. Presence and the content hash (for caching) are on `AppGroupRecordFfi::image_hash_hex`; when the group also carries a URL avatar, the URL takes precedence for rendering.

[Source](src/commands/group.rs#L1003)

### `Marmot::update_group_avatar_url`

**Current.**

```rust
pub async fn update_group_avatar_url( &self, account_ref: String, group_id_hex: String, url: Option<String>, dim: Option<String>, thumbhash: Option<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Set (or clear, with `url = None`) the group's URL-based avatar (`marmot.group.avatar-url.v1`). The URL is validated (https-only, no localhost/private hosts) and normalized before it is committed.

[Source](src/commands/group.rs#L1019)

### `Marmot::replace_encrypted_media_blob_endpoints`

**Current.**

```rust
pub async fn replace_encrypted_media_blob_endpoints( &self, account_ref: String, group_id_hex: String, endpoints: Vec<AppBlobEndpointFfi>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Replace the group's encrypted-media default blob endpoints as a full `marmot.group.encrypted-media.v1` component update. Requires the caller to be an admin.

[Source](src/commands/group.rs#L1038)

### `Marmot::promote_admin`

**Current.**

```rust
pub async fn promote_admin( &self, account_ref: String, group_id_hex: String, member_ref: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Grant admin rights to `member_ref` (npub or hex). Requires the caller to be an admin; publishes a group state update.

[Source](src/commands/group.rs#L1058)

### `Marmot::demote_admin`

**Current.**

```rust
pub async fn demote_admin( &self, account_ref: String, group_id_hex: String, member_ref: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Revoke `member_ref`'s admin rights.

[Source](src/commands/group.rs#L1077)

### `Marmot::self_demote_admin`

**Current.**

```rust
pub async fn self_demote_admin( &self, account_ref: String, group_id_hex: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Step down as an admin of `group_id_hex` (demote the active account).

[Source](src/commands/group.rs#L1096)

### `Marmot::invite_members_detailed`

**Current.**

```rust
pub async fn invite_members_detailed( &self, account_ref: String, group_id_hex: String, member_refs: Vec<String>, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Same as `Self::invite_members`, returning the post-mutation group snapshot.

[Source](src/commands/group.rs#L1115)

### `Marmot::invite_members_detailed_with_initial_admins`

**Current.**

```rust
pub async fn invite_members_detailed_with_initial_admins( &self, account_ref: String, group_id_hex: String, member_refs: Vec<String>, initial_admin_refs: Vec<String>, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Same as `Self::invite_members_with_initial_admins`, returning the post-mutation group snapshot.

[Source](src/commands/group.rs#L1132)

### `Marmot::remove_members_detailed`

**Current.**

```rust
pub async fn remove_members_detailed( &self, account_ref: String, group_id_hex: String, member_refs: Vec<String>, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Remove selected members and return detailed operation outcome.

[Source](src/commands/group.rs#L1157)

### `Marmot::promote_admin_detailed`

**Current.**

```rust
pub async fn promote_admin_detailed( &self, account_ref: String, group_id_hex: String, member_ref: String, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Promote selected members and return detailed operation outcome.

[Source](src/commands/group.rs#L1176)

### `Marmot::demote_admin_detailed`

**Current.**

```rust
pub async fn demote_admin_detailed( &self, account_ref: String, group_id_hex: String, member_ref: String, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Demote selected administrators and return detailed operation outcome.

[Source](src/commands/group.rs#L1195)

### `Marmot::self_demote_admin_detailed`

**Current.**

```rust
pub async fn self_demote_admin_detailed( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupMutationResultFfi, MarmotKitError>
```

Demote the current account and return detailed operation outcome.

[Source](src/commands/group.rs#L1214)

### `Marmot::group_mls_state`

**Current.**

```rust
pub async fn group_mls_state( &self, account_ref: String, group_id_hex: String, ) -> Result<AppGroupMlsStateFfi, MarmotKitError>
```

Current MLS state (epoch, member count, required components) for the conversation developer/debug view.

[Source](src/commands/group.rs#L1234)

### `Marmot::quarantined_groups`

**Current.**

```rust
pub async fn quarantined_groups( &self, account_ref: String, ) -> Result<Vec<AppQuarantinedGroupFfi>, MarmotKitError>
```

Stored groups that failed session-open hydration and were skipped so the rest of the account could open (mdk#151 / #417). These groups are not in the live roster and otherwise vanish from the account with no explanation; surface them in a per-group recovery flow (mdk#426) distinct from healthy and archived groups, using `reason` to pick the per-reason guidance, and offer `Self::retry_hydrate_quarantined_group`.

[Source](src/commands/group.rs#L1254)

### `Marmot::retry_hydrate_quarantined_group`

**Current.**

```rust
pub async fn retry_hydrate_quarantined_group( &self, account_ref: String, group_id_hex: String, ) -> Result<bool, MarmotKitError>
```

Re-attempt hydration of a single quarantined group (mdk#426).

[Source](src/commands/group.rs#L1270)

### `Marmot::set_group_archived`

**Current.**

```rust
pub async fn set_group_archived( &self, account_ref: String, group_id_hex: String, archived: bool, ) -> Result<AppGroupRecordFfi, MarmotKitError>
```

Flag a group archived (or restore it). Local-only projection state — it does not change membership or publish anything. The chats list filters archived groups unless `include_archived` is set.

[Source](src/commands/group.rs#L1285)

### `Marmot::group_maintenance_status`

**Current.**

```rust
pub async fn group_maintenance_status( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupMaintenanceStatusFfi, MarmotKitError>
```

Inspect maintenance status for a group.

[Source](src/commands/group.rs#L1300)

### `Marmot::key_package_maintenance_status`

**Current.**

```rust
pub async fn key_package_maintenance_status( &self, account_ref: String, ) -> Result<Option<KeyPackageMaintenanceStatusFfi>, MarmotKitError>
```

Inspect account KeyPackage maintenance status.

[Source](src/commands/group.rs#L1313)

### `Marmot::schedule_group_self_update`

**Current.**

```rust
pub async fn schedule_group_self_update( &self, account_ref: String, group_id_hex: String, ) -> Result<String, MarmotKitError>
```

Schedule a group self-update.

[Source](src/commands/group.rs#L1324)

### `Marmot::periodic_maintenance_policy`

**Current.**

```rust
pub async fn periodic_maintenance_policy( &self, account_ref: String, ) -> Result<PeriodicMaintenancePolicyFfi, MarmotKitError>
```

Read periodic maintenance policy.

[Source](src/commands/group.rs#L1336)

### `Marmot::set_periodic_maintenance_policy`

**Current.**

```rust
pub async fn set_periodic_maintenance_policy( &self, account_ref: String, policy: PeriodicMaintenancePolicyFfi, ) -> Result<(), MarmotKitError>
```

Set periodic maintenance policy.

[Source](src/commands/group.rs#L1347)

### `Marmot::pause_maintenance`

**Current.**

```rust
pub async fn pause_maintenance(&self, account_ref: String) -> Result<(), MarmotKitError>
```

Pause maintenance for an account.

[Source](src/commands/group.rs#L1358)

### `Marmot::resume_maintenance`

**Current.**

```rust
pub async fn resume_maintenance(&self, account_ref: String) -> Result<(), MarmotKitError>
```

Resume maintenance for an account.

[Source](src/commands/group.rs#L1362)

### `Marmot::run_due_maintenance`

**Current.**

```rust
pub async fn run_due_maintenance( &self, account_ref: String, ) -> Result<MaintenanceRunSummaryFfi, MarmotKitError>
```

Run due maintenance for an account.

[Source](src/commands/group.rs#L1366)

</details>

<details>
<summary>commands/media.rs</summary>

### `parse_media_imeta_tag`

**Current free function.** Generated Swift/Kotlin name: `parseMediaImetaTag`.

```rust
pub fn parse_media_imeta_tag( tag: MessageTagFfi, source_epoch: u64, ) -> Result<MediaAttachmentReferenceFfi, MarmotKitError>
```

Parse one authenticated encrypted-media `imeta` tag using MDK's frozen V1 or current V2 validation rules.

[Source](src/commands/media.rs#L23)

### `Marmot::build_media_imeta_tag`

**Current.**

```rust
pub async fn build_media_imeta_tag( &self, account_ref: String, group_id_hex: String, reference: MediaAttachmentReferenceFfi, ) -> Result<MessageTagFfi, MarmotKitError>
```

Build one outbound encrypted-media `imeta` tag without publishing it.

[Source](src/commands/media.rs#L39)

### `Marmot::send_media_attachments`

**Current.**

```rust
pub async fn send_media_attachments( &self, account_ref: String, group_id_hex: String, attachments: Vec<MediaAttachmentReferenceFfi>, caption: Option<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Send already-uploaded encrypted media attachments as a kind-9 chat carrying ordered NIP-92 `imeta` tags.

[Source](src/commands/media.rs#L56)

### `Marmot::send_media_reference`

**Current.**

```rust
pub async fn send_media_reference( &self, account_ref: String, group_id_hex: String, reference: MediaAttachmentReferenceFfi, caption: Option<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Backward-compatible single-attachment send helper. Prefer `send_media_attachments` for new callers so one chat can carry ordered mixed media attachments.

[Source](src/commands/media.rs#L80)

### `Marmot::upload_media`

**Current.**

```rust
pub async fn upload_media( &self, account_ref: String, group_id_hex: String, request: MediaUploadRequestFfi, ) -> Result<MediaUploadResultFfi, MarmotKitError>
```

Encrypt plaintext attachments, upload the ciphertext blobs, and optionally send the resulting media references into the group.

[Source](src/commands/media.rs#L93)

### `Marmot::download_media`

**Compatibility.** Prefer retained local access plus transfer controls for received chat media. Explicit one-shot fetch remains supported.

```rust
pub async fn download_media( &self, account_ref: String, group_id_hex: String, reference: MediaAttachmentReferenceFfi, ) -> Result<MediaDownloadResultFfi, MarmotKitError>
```

Fetch an encrypted media blob and decrypt it using the group's encrypted media component secret.

[Source](src/commands/media.rs#L117)

### `Marmot::list_media`

**Compatibility.** Prefer attachment_history_page/version for new media-library screens.

```rust
pub fn list_media( &self, account_ref: String, group_id_hex: String, limit: Option<u32>, ) -> Result<Vec<MediaRecordFfi>, MarmotKitError>
```

Typed media references projected from group message history. Host apps can pass a returned `reference` back to `download_media`.

[Source](src/commands/media.rs#L138)

</details>

<details>
<summary>commands/message.rs</summary>

### `Marmot::send_text`

**Current.**

```rust
pub async fn send_text( &self, account_ref: String, group_id_hex: String, text: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Send a plain UTF-8 text message. Structured payloads (reactions, replies, deletes, media) go through dedicated methods.

[Source](src/commands/message.rs#L21)

### `Marmot::retry_group_convergence`

**Current.**

```rust
pub async fn retry_group_convergence( &self, account_ref: String, group_id_hex: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Re-attempt publishing a group's pending (committed-but-undelivered) commit(s) without minting a new event.

[Source](src/commands/message.rs#L54)

### `Marmot::react_to_message`

**Current.**

```rust
pub async fn react_to_message( &self, account_ref: String, group_id_hex: String, target_message_id: String, emoji: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

React to `target_message_id` with `emoji` (an "add" reaction).

[Source](src/commands/message.rs#L68)

### `Marmot::unreact_from_message`

**Current.**

```rust
pub async fn unreact_from_message( &self, account_ref: String, group_id_hex: String, target_message_id: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Remove all of this account's active reactions from `target_message_id`.

[Source](src/commands/message.rs#L84)

### `Marmot::reply_to_message`

**Current.**

```rust
pub async fn reply_to_message( &self, account_ref: String, group_id_hex: String, target_message_id: String, text: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Send `text` as a reply that quotes `target_message_id`.

[Source](src/commands/message.rs#L99)

### `Marmot::delete_message`

**Current.**

```rust
pub async fn delete_message( &self, account_ref: String, group_id_hex: String, target_message_id: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Mark `target_message_id` deleted for the whole group. This is a tombstone — the original stays in everyone's store; clients render a "message deleted" placeholder.

[Source](src/commands/message.rs#L117)

### `Marmot::secure_delete_expired`

**Current.**

```rust
pub async fn secure_delete_expired( &self, account_ref: String, group_id_hex: String, ) -> Result<SecureDeleteExpiredResultFfi, MarmotKitError>
```

Securely scrub and prune expired disappearing-message plaintext for a group according to its active retention component. The media hash list identifies pruned encrypted-media blobs so host apps can purge their own decrypted-media disk caches keyed by ciphertext hash.

[Source](src/commands/message.rs#L135)

### `Marmot::sweep_expired_retention`

**Current.**

```rust
pub async fn sweep_expired_retention( &self, account_ref: String, now_ms: u64, ) -> Result<RetentionSweepReportFfi, MarmotKitError>
```

Run the engine-owned disappearing-message sweep for one account using the supplied Unix wall-clock time in milliseconds. Each group reports pruning, a fail-closed deferral, or a privacy-safe failure category.

[Source](src/commands/message.rs#L151)

### `Marmot::edit_message`

**Current.**

```rust
pub async fn edit_message( &self, account_ref: String, group_id_hex: String, target_message_id: String, content: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Edit `target_message_id` by publishing a kind-1009 event that references it and carries the replacement plaintext in `content`. Recipients honour the edit only when its authenticated author matches the target's author; MDK ignores mismatched edits.

[Source](src/commands/message.rs#L172)

### `Marmot::send_custom_event`

**Current.**

```rust
pub async fn send_custom_event( &self, account_ref: String, group_id_hex: String, kind: u64, tags: Vec<Vec<String>>, content: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Send an app-defined event with an arbitrary non-reserved kind. `tags` and `content` pass through verbatim; kinds MDK owns (chat, reaction, edit, delete, agent, group system, push token) are rejected so an app cannot forge protocol events. Custom events appear in the timeline as standalone rows and can be fetched via `Marmot::messages` with a `kinds` filter.

[Source](src/commands/message.rs#L193)

### `Marmot::create_poll`

**Current.** Typed API for an encrypted NIP-88 group poll; do not build kinds 1068/1018 through `send_custom_event`.

```rust
pub async fn create_poll( &self, account_ref: String, group_id_hex: String, question: String, options: Vec<String>, poll_type: PollTypeFfi, ends_at: Option<u64>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Pass two through ten option labels and an optional Unix-seconds deadline no more than 30 days after creation. MDK
validates bounded display text, assigns stable option ids in display order, and exposes results through the timeline
poll projection. Creation follows MDK's canonical conversation classification: named two-member conversations are
groups, while unnamed two-member conversations are direct. Polls are neither anonymous nor election-grade. See
[Polls](POLLS.md).

[Source](src/commands/message.rs#L211)

### `Marmot::cast_poll_vote`

**Current.** Use for a complete replacement selection on an existing encrypted group poll.

```rust
pub async fn cast_poll_vote( &self, account_ref: String, group_id_hex: String, poll_event_id: String, option_ids: Vec<String>, ) -> Result<SendSummaryFfi, MarmotKitError>
```

The poll must already be a valid local timeline row in this group and remain open. Pass one option id for single choice
or one through ten unique ids for multiple choice; use the ids from `TimelineMessageRecordFfi.poll`, not option labels.
This is a replacement, not a delta or unvote. MDK revalidates the poll against the response event's actual timestamp at
send time, and an accepted open poll remains votable after conversation reclassification. See [Polls](POLLS.md).

[Source](src/commands/message.rs#L236)

### `Marmot::messages`

**Lower-level.** Raw stored messages; complete conversation screens use open_conversation_window.

```rust
pub fn messages( &self, account_ref: String, group_id_hex: Option<String>, limit: Option<u32>, kinds: Option<Vec<u64>>, ) -> Result<Vec<AppMessageRecordFfi>, MarmotKitError>
```

Initial history fetch for a group (or, when `group_id_hex` is None, the account-wide tail). Used to populate the conversation view before the subscription stream takes over.

[Source](src/commands/message.rs#L257)

</details>

<details>
<summary>commands/moderation.rs</summary>

### `Marmot::report_message`

**Current.**

```rust
pub async fn report_message( &self, account_ref: String, group_id_hex: String, message_id: String, reason: ReportReasonFfi, explanation: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Publish a report with a typed reason and explanation for a target message.

[Source](src/commands/moderation.rs#L110)

### `Marmot::dismiss_reports`

**Current.**

```rust
pub async fn dismiss_reports( &self, account_ref: String, group_id_hex: String, report_ids: Vec<String>, explanation: String, ) -> Result<SendSummaryFfi, MarmotKitError>
```

Publish an admin dismissal label for selected reports.

[Source](src/commands/moderation.rs#L130)

### `Marmot::content_reports`

**Current.**

```rust
pub fn content_reports( &self, account_ref: String, group_id_hex: String, message_id: Option<String>, after: Option<String>, limit: u32, ) -> Result<ContentReportPageFfi, MarmotKitError>
```

Read a bounded page of reports with per-report dismissal state.

[Source](src/commands/moderation.rs#L148)

### `Marmot::reported_message`

**Current.**

```rust
pub fn reported_message( &self, account_ref: String, group_id_hex: String, message_id: String, ) -> Result<Option<TimelineMessageRecordFfi>, MarmotKitError>
```

Read the report target through deletion-masked timeline presentation.

[Source](src/commands/moderation.rs#L167)

### `Marmot::report_dismissals`

**Current.**

```rust
pub fn report_dismissals( &self, account_ref: String, group_id_hex: String, report_id: String, after: Option<String>, limit: u32, ) -> Result<ReportDismissalPageFfi, MarmotKitError>
```

Read a bounded page of dismissal labels.

[Source](src/commands/moderation.rs#L182)

</details>

<details>
<summary>commands/notification.rs</summary>

### `Marmot::notification_settings`

**Current.**

```rust
pub fn notification_settings( &self, account_ref: String, ) -> Result<NotificationSettingsFfi, MarmotKitError>
```

Read account notification settings.

[Source](src/commands/notification.rs#L15)

### `Marmot::set_local_notifications_enabled`

**Current.**

```rust
pub fn set_local_notifications_enabled( &self, account_ref: String, enabled: bool, ) -> Result<NotificationSettingsFfi, MarmotKitError>
```

Set local notification generation preference.

[Source](src/commands/notification.rs#L22)

### `Marmot::set_native_push_enabled`

**Current.**

```rust
pub async fn set_native_push_enabled( &self, account_ref: String, enabled: bool, ) -> Result<NotificationSettingsFfi, MarmotKitError>
```

Set native push preference.

[Source](src/commands/notification.rs#L33)

### `Marmot::catch_up_accounts`

**Current.**

```rust
pub async fn catch_up_accounts(&self) -> Result<(), MarmotKitError>
```

Run bounded account catch-up work.

[Source](src/commands/notification.rs#L45)

### `Marmot::notify_connectivity_restored`

**Current.**

```rust
pub async fn notify_connectivity_restored(&self) -> Result<(), MarmotKitError>
```

Interrupt retry backoff for durable outbound work after the host has observed usable connectivity. This is a scheduling signal only; it does not recreate application events or weaken exact-replay guarantees.

[Source](src/commands/notification.rs#L53)

### `Marmot::collect_notifications_after_wake`

**Current.**

```rust
pub async fn collect_notifications_after_wake( &self, max_wait_ms: u32, source: NotificationWakeSourceFfi, ) -> Result<BackgroundNotificationCollectionFfi, MarmotKitError>
```

Collect notifications after bounded wake/catch-up processing.

[Source](src/commands/notification.rs#L58)

</details>

<details>
<summary>commands/onboarding.rs</summary>

### `OnboardingSubscription::snapshot`

**Current.**

```rust
pub fn snapshot(&self) -> OnboardingSnapshotFfi
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/commands/onboarding.rs#L18)

### `OnboardingSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Option<OnboardingSnapshotFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/commands/onboarding.rs#L21)

### `Marmot::onboarding_recovery_required`

**Current.**

```rust
pub fn onboarding_recovery_required( &self, account_ref: String, ) -> Result<bool, MarmotKitError>
```

Whether an unreadable or exhausted checkpoint needs explicit recovery.

[Source](src/commands/onboarding.rs#L28)

### `Marmot::recover_onboarding`

**Current.**

```rust
pub async fn recover_onboarding( &self, account_ref: String, acknowledge_latest_only_evidence: bool, ) -> Result<String, MarmotKitError>
```

Preserve opaque evidence, sign out, and retire the old attempt. Hosts invalidate old UI callbacks first, acknowledge latest-only retention, then explicitly begin again and use the snapshot's recovery_epoch.

[Source](src/commands/onboarding.rs#L41)

### `Marmot::approve_onboarding_repair_in_epoch`

**Current.**

```rust
pub async fn approve_onboarding_repair_in_epoch( &self, account_ref: String, revision: u64, recovery_epoch: String, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Approve with the epoch and revision from the same displayed snapshot.

[Source](src/commands/onboarding.rs#L54)

### `Marmot::acknowledge_onboarding_single_device_in_epoch`

**Current.**

```rust
pub async fn acknowledge_onboarding_single_device_in_epoch( &self, account_ref: String, revision: u64, recovery_epoch: String, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Acknowledge with the epoch and revision from the displayed device notice.

[Source](src/commands/onboarding.rs#L69)

### `Marmot::cancel_onboarding`

**Current.**

```rust
pub async fn cancel_onboarding(&self, account_ref: String) -> Result<(), MarmotKitError>
```

Cancel the current interactive onboarding attempt at any step, including approved or ready checkpoints. The identity stays signed out. Already journaled evidence is retained in the latest cancellation checkpoint; later cancellations replace it even if publication remains uncertain. A later explicit `begin_*_onboarding` starts a new attempt. Hosts should invalidate the UI attempt, ignore the old subscription, and await this call before beginning again. Open Chats stays host-owned.

[Source](src/commands/onboarding.rs#L89)

### `Marmot::acknowledge_onboarding_single_device`

**Current.**

```rust
pub async fn acknowledge_onboarding_single_device( &self, account_ref: String, revision: u64, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Record Continue anyway for the displayed notice, then resume setup.

[Source](src/commands/onboarding.rs#L98)

### `Marmot::begin_onboarding`

**Current.**

```rust
pub async fn begin_onboarding( &self, nsec: String, options: OnboardingOptionsFfi, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Persist the identity and return before any network preflight or publication.

[Source](src/commands/onboarding.rs#L111)

### `Marmot::begin_external_signer_onboarding`

**Current.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
pub async fn begin_external_signer_onboarding( &self, public_key: String, signer: Arc<dyn ExternalAccountSignerFfi>, options: OnboardingOptionsFfi, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Begin interactive identity-only onboarding with a host signer; signer remains host-owned and must be registered after reconstruction.

[Source](src/commands/onboarding.rs#L123)

### `Marmot::onboarding_snapshot`

**Current.**

```rust
pub fn onboarding_snapshot( &self, account_ref: String, ) -> Result<Option<OnboardingSnapshotFfi>, MarmotKitError>
```

Read the persisted onboarding state.

[Source](src/commands/onboarding.rs#L140)

### `Marmot::subscribe_onboarding`

**Current.**

```rust
pub fn subscribe_onboarding( &self, account_ref: String, ) -> Result<Arc<OnboardingSubscription>, MarmotKitError>
```

Observe onboarding snapshots for one account.

[Source](src/commands/onboarding.rs#L150)

### `Marmot::set_onboarding_discovery_relays`

**Current.**

```rust
pub async fn set_onboarding_discovery_relays( &self, account_ref: String, discovery_relays: Vec<String>, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Change discovery sources for the workflow without publishing them as account relay lists.

[Source](src/commands/onboarding.rs#L160)

### `Marmot::run_onboarding`

**Current.**

```rust
pub async fn run_onboarding( &self, account_ref: String, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Run/resume the durable onboarding workflow until ready or user input is required.

[Source](src/commands/onboarding.rs#L172)

### `Marmot::retry_onboarding_step`

**Current.**

```rust
pub async fn retry_onboarding_step( &self, account_ref: String, step: OnboardingStepFfi, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Retry a step whose current snapshot offers Retry.

[Source](src/commands/onboarding.rs#L183)

### `Marmot::continue_onboarding_without`

**Current.**

```rust
pub async fn continue_onboarding_without( &self, account_ref: String, step: OnboardingStepFfi, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Explicitly skip an optional step where the current snapshot permits it.

[Source](src/commands/onboarding.rs#L195)

### `Marmot::propose_onboarding_recommended_relays`

**Current.**

```rust
pub async fn propose_onboarding_recommended_relays( &self, account_ref: String, step: OnboardingStepFfi, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Prepare recommended relay changes for approval; proposal alone is not publication.

[Source](src/commands/onboarding.rs#L207)

### `Marmot::propose_onboarding_relays`

**Current.**

```rust
pub async fn propose_onboarding_relays( &self, account_ref: String, step: OnboardingStepFfi, read_relays: Vec<String>, write_relays: Vec<String>, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Prepare explicit relay changes for approval.

[Source](src/commands/onboarding.rs#L219)

### `Marmot::propose_onboarding_profile`

**Current.**

```rust
pub async fn propose_onboarding_profile( &self, account_ref: String, profile: UserProfileMetadataFfi, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Prepare profile changes for approval.

[Source](src/commands/onboarding.rs#L233)

### `Marmot::propose_onboarding_follows`

**Current.**

```rust
pub async fn propose_onboarding_follows( &self, account_ref: String, follows: Vec<String>, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Prepare follow-list changes for approval.

[Source](src/commands/onboarding.rs#L245)

### `Marmot::approve_onboarding_repair`

**Current.**

```rust
pub async fn approve_onboarding_repair( &self, account_ref: String, revision: u64, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Approve the displayed revision for a non-recovered attempt; recovered attempts require the epoch-aware method.

[Source](src/commands/onboarding.rs#L257)

### `Marmot::cancel_onboarding_repair`

**Current.**

```rust
pub async fn cancel_onboarding_repair( &self, account_ref: String, ) -> Result<OnboardingSnapshotFfi, MarmotKitError>
```

Dismiss an unapproved repair proposal; this cannot undo already-approved publication intent.

[Source](src/commands/onboarding.rs#L269)

</details>

<details>
<summary>commands/presentation.rs</summary>

### `Marmot::presented_chat_list`

**Lower-level.** Selected full list; default paged screens use open_chat_list_window.

```rust
pub async fn presented_chat_list( &self, account_ref: String, include_archived: bool, ) -> Result<PresentedChatListSnapshotFfi, MarmotKitError>
```

Local whole rows, including selected title/avatar. First use may await local preparation.

[Source](src/commands/presentation.rs#L10)

### `Marmot::presented_chat_list_row`

**Current.**

```rust
pub async fn presented_chat_list_row( &self, account_ref: String, group_id_hex: String, ) -> Result<Option<PresentedChatRowFfi>, MarmotKitError>
```

One complete row for creation/rebind; missing local groups return None.

[Source](src/commands/presentation.rs#L22)

### `Marmot::open_presented_chat_list`

**Lower-level.** Live selected full list; default paged screens use open_chat_list_window.

```rust
pub async fn open_presented_chat_list( &self, account_ref: String, include_archived: bool, ) -> Result<Arc<PresentedChatListSubscription>, MarmotKitError>
```

Returns an attached handle containing the initial snapshot. Take its snapshot once, then consume whole replacement updates; dispose the old handle on account switch.

[Source](src/commands/presentation.rs#L35)

</details>

<details>
<summary>commands/product_analytics.rs</summary>

### `Marmot::usage_diagnostics_settings`

**Current.**

```rust
pub fn usage_diagnostics_settings( &self, ) -> Result<UsageDiagnosticsSettingsFfi, MarmotKitError>
```

Read durable diagnostics-consent settings.

[Source](src/commands/product_analytics.rs#L5)

### `Marmot::set_usage_diagnostics_consent`

**Current.**

```rust
pub fn set_usage_diagnostics_consent( &self, enabled: bool, ) -> Result<UsageDiagnosticsSettingsFfi, MarmotKitError>
```

Persist the user diagnostics-consent choice.

[Source](src/commands/product_analytics.rs#L10)

### `Marmot::usage_diagnostics_status`

**Current.**

```rust
pub fn usage_diagnostics_status(&self) -> Result<UsageDiagnosticsStatusFfi, MarmotKitError>
```

Read diagnostics configuration/delivery status.

[Source](src/commands/product_analytics.rs#L16)

### `Marmot::set_product_analytics_runtime_config`

**Current.**

```rust
pub fn set_product_analytics_runtime_config( &self, config: ProductAnalyticsRuntimeConfigFfi, ) -> Result<(), MarmotKitError>
```

Configure the consent-gated product-event pipeline.

[Source](src/commands/product_analytics.rs#L19)

### `Marmot::record_product_event`

**Current.**

```rust
pub fn record_product_event( &self, event: ProductEventFfi, ) -> Result<ProductRecordResultFfi, MarmotKitError>
```

Record an event accepted by the configured closed product-event schema and consent policy.

[Source](src/commands/product_analytics.rs#L37)

### `Marmot::set_product_analytics_activity`

**Current.**

```rust
pub async fn set_product_analytics_activity( &self, activity: ProductAnalyticsActivityFfi, ) -> Result<(), MarmotKitError>
```

Update host activity state for product analytics.

[Source](src/commands/product_analytics.rs#L43)

### `Marmot::flush_product_analytics`

**Current.**

```rust
pub async fn flush_product_analytics(&self) -> Result<(), MarmotKitError>
```

Flush pending eligible product analytics work.

[Source](src/commands/product_analytics.rs#L52)

</details>

<details>
<summary>commands/push.rs</summary>

### `Marmot::push_registration`

**Current.**

```rust
pub fn push_registration( &self, account_ref: String, ) -> Result<Option<PushRegistrationFfi>, MarmotKitError>
```

Read an account native-push registration.

[Source](src/commands/push.rs#L12)

### `Marmot::upsert_push_registration`

**Current.**

```rust
pub async fn upsert_push_registration( &self, account_ref: String, platform: PushPlatformFfi, raw_token: String, server_pubkey_hex: String, relay_hint: Option<String>, ) -> Result<PushRegistrationSyncResultFfi, MarmotKitError>
```

Register/update native push configuration with account ownership proof.

[Source](src/commands/push.rs#L22)

### `Marmot::clear_push_registration`

**Current.**

```rust
pub async fn clear_push_registration( &self, account_ref: String, ) -> Result<PushRegistrationShareOutcomeFfi, MarmotKitError>
```

Clear the account native-push registration.

[Source](src/commands/push.rs#L44)

### `Marmot::group_push_debug_info`

**Current.**

```rust
pub async fn group_push_debug_info( &self, account_ref: String, group_id_hex: String, ) -> Result<GroupPushDebugInfoFfi, MarmotKitError>
```

Inspect group push-routing debug information; do not log sensitive identifiers indiscriminately.

[Source](src/commands/push.rs#L55)

</details>

<details>
<summary>commands/relay.rs</summary>

### `Marmot::retired_relay_hosts`

**Current.**

```rust
pub fn retired_relay_hosts(&self) -> Vec<String>
```

Hostnames the relay plane will never dial or adopt.

[Source](src/commands/relay.rs#L12)

### `Marmot::classify_relay_endpoints`

**Current.**

```rust
pub fn classify_relay_endpoints( &self, endpoints: Vec<String>, ) -> Vec<RelayEndpointClassificationFfi>
```

Classify relay URLs using the same policy enforced at the dial boundary.

[Source](src/commands/relay.rs#L20)

### `Marmot::account_relay_lists`

**Current.**

```rust
pub fn account_relay_lists( &self, account_ref: String, ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError>
```

Per-account relay lists: the NIP-65 and inbox lists the account has published, plus the configured default/bootstrap sets.

[Source](src/commands/relay.rs#L35)

### `Marmot::relay_health`

**Current.**

```rust
pub async fn relay_health(&self) -> conversions::RelayHealthFfi
```

Live relay-plane connection health (connected / connecting / disconnected counts, etc.) for the relay diagnostics view.

[Source](src/commands/relay.rs#L46)

### `Marmot::relay_telemetry_settings`

**Current.**

```rust
pub fn relay_telemetry_settings(&self) -> Result<RelayTelemetrySettingsFfi, MarmotKitError>
```

Device-wide relay telemetry export settings. Export is opt-in and stays inert until `export_enabled` is true and runtime/default config supplies a valid OTLP endpoint, bearer token, and resource attributes.

[Source](src/commands/relay.rs#L54)

### `Marmot::telemetry_install_id`

**Current.**

```rust
pub fn telemetry_install_id(&self) -> Result<String, MarmotKitError>
```

Consent-bound random OTLP identifier, stable until revocation. Requires a current combined grant; never use this value in product events.

[Source](src/commands/relay.rs#L60)

### `Marmot::set_relay_telemetry_runtime_config`

**Current.**

```rust
pub async fn set_relay_telemetry_runtime_config( &self, config: RelayTelemetryRuntimeConfigFfi, ) -> Result<(), MarmotKitError>
```

Supply non-persisted OTLP runtime metadata: optional metrics URL override, bearer token from the host app's build-time secret, and resource attributes from the platform shell.

[Source](src/commands/relay.rs#L67)

### `Marmot::set_relay_telemetry_settings`

**Current.**

```rust
pub async fn set_relay_telemetry_settings( &self, settings: RelayTelemetrySettingsFfi, ) -> Result<RelayTelemetrySettingsFfi, MarmotKitError>
```

Deprecated consent control. Use `set_usage_diagnostics_consent` instead. Enable requires a combined grant; disable revokes both exporters. This compatibility setter still updates the telemetry interval.

[Source](src/commands/relay.rs#L79)

</details>

<details>
<summary>commands/subscription.rs</summary>

### `Marmot::subscribe_events`

**Current.**

```rust
pub fn subscribe_events(&self) -> Arc<EventsSubscription>
```

Top-level event firehose. One subscription, every account, every event type. Useful for global diagnostics; specific UIs prefer the per-account chats/messages/group-state subscriptions below.

[Source](src/commands/subscription.rs#L27)

### `Marmot::subscribe_notifications`

**Current.**

```rust
pub async fn subscribe_notifications( &self, ) -> Result<Arc<NotificationsSubscription>, MarmotKitError>
```

Observe prepared runtime notification events.

[Source](src/commands/subscription.rs#L31)

### `Marmot::subscribe_chats`

**Lower-level.** Raw chat/group subscription; prepared screens use open_chat_list_window.

```rust
pub async fn subscribe_chats( &self, account_ref: String, include_archived: bool, ) -> Result<Arc<ChatsSubscription>, MarmotKitError>
```

Per-account chats list. Emits whenever a group's projection changes.

[Source](src/commands/subscription.rs#L44)

### `Marmot::subscribe_chat_list`

**Lower-level.** Raw list subscription; prepared screens use open_chat_list_window.

```rust
pub async fn subscribe_chat_list( &self, account_ref: String, include_archived: bool, ) -> Result<Arc<ChatListSubscription>, MarmotKitError>
```

Per-account durable chat-list projection. Async for the same tokio-runtime reason as `Marmot::subscribe_chats`.

[Source](src/commands/subscription.rs#L58)

### `Marmot::subscribe_messages`

**Lower-level.** Raw message subscription; complete screens use open_conversation_window.

```rust
pub async fn subscribe_messages( &self, account_ref: String, group_id_hex: Option<String>, limit: Option<u32>, kinds: Option<Vec<u64>>, ) -> Result<Arc<MessagesSubscription>, MarmotKitError>
```

Messages for a specific group (when `group_id_hex` is `Some`) or every message across the account (when `None`). `limit` caps the initial snapshot to the latest N rows; live updates continue after the snapshot. `kinds` restricts to the listed inner app-event kinds (e.g. an app-defined custom kind); `None` or an empty list streams all kinds. Async for the same tokio-runtime reason as `Marmot::subscribe_chats`.

[Source](src/commands/subscription.rs#L76)

### `Marmot::subscribe_timeline_messages`

**Lower-level.** Custom timeline subscription; complete screens use open_conversation_window.

```rust
pub async fn subscribe_timeline_messages( &self, account_ref: String, group_id_hex: Option<String>, limit: Option<u32>, ) -> Result<Arc<TimelineMessagesSubscription>, MarmotKitError>
```

Live materialized timeline updates for a group or account-wide tail. The snapshot and each update are full pages for the supplied query.

[Source](src/commands/subscription.rs#L94)

### `Marmot::subscribe_group_state`

**Current.**

```rust
pub async fn subscribe_group_state( &self, account_ref: String, group_id_hex: String, ) -> Result<Arc<GroupStateSubscription>, MarmotKitError>
```

Member/profile/roster changes for one group. Async for the same tokio-runtime reason as `Marmot::subscribe_chats`.

[Source](src/commands/subscription.rs#L117)

</details>

<details>
<summary>commands/telemetry.rs</summary>

### `Marmot::record_host_timing`

**Current.**

```rust
pub fn record_host_timing( &self, name: String, duration_ms: u64, outcome: HostPerformanceOutcomeFfi, ) -> Result<ProductRecordResultFfi, MarmotKitError>
```

Record an app-defined timing in the consent-gated product event pipeline. Register `name` with `elapsed: DurationBucket` and `outcome: Enum` choices `success`/`failure` in the product analytics config. Milliseconds are bucketed before recording; this does not add an OTLP performance metric.

[Source](src/commands/telemetry.rs#L17)

### `Marmot::record_host_performance`

**Current.**

```rust
pub fn record_host_performance( &self, operation: HostPerformanceOperationFfi, duration_ms: u64, outcome: HostPerformanceOutcomeFfi, )
```

Record one approved host-app milestone.

[Source](src/commands/telemetry.rs#L33)

### `Marmot::app_performance_snapshot`

**Current.**

```rust
pub fn app_performance_snapshot(&self) -> AppPerformanceSnapshotFfi
```

Read the process-wide app-performance snapshot for debug/diagnostics surfaces and on-demand support dumps.

[Source](src/commands/telemetry.rs#L52)

</details>

<details>
<summary>commands/timeline.rs</summary>

### `Marmot::message_edit_history`

**Current.**

```rust
pub fn message_edit_history( &self, account_ref: String, group_id_hex: String, target_message_id_hex: String, before_edited_at: Option<u64>, before_message_id_hex: Option<String>, limit: u32, ) -> Result<crate::conversions::TimelineEditHistoryPageFfi, MarmotKitError>
```

Accepted edit versions, oldest first within a latest-first page (1..=100). Supply both cursor fields from the first version to load older versions. Run this synchronous details query off the UI thread; screens already carry effective content.

[Source](src/commands/timeline.rs#L12)

### `Marmot::timeline_messages`

**Lower-level.** Custom timeline page; complete conversation screens use open_conversation_window.

```rust
pub fn timeline_messages( &self, account_ref: String, query: TimelineMessageQueryFfi, ) -> Result<TimelinePageFfi, MarmotKitError>
```

Materialized conversation timeline for a group or account-wide tail.

[Source](src/commands/timeline.rs#L57)

</details>

<details>
<summary>commands/user_blocks.rs</summary>

### `BlockListSubscription::snapshot`

**Current.**

```rust
pub fn snapshot(&self) -> Option<BlockListSnapshotFfi>
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/commands/user_blocks.rs#L41)

### `BlockListSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Option<BlockListSnapshotFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/commands/user_blocks.rs#L44)

### `Marmot::block_user`

**Current.**

```rust
pub async fn block_user( &self, account_ref: String, user_account_id_hex: String, ) -> Result<(), MarmotKitError>
```

Block a user for the account.

[Source](src/commands/user_blocks.rs#L50)

### `Marmot::unblock_user`

**Current.**

```rust
pub async fn unblock_user( &self, account_ref: String, user_account_id_hex: String, ) -> Result<(), MarmotKitError>
```

Remove a user block.

[Source](src/commands/user_blocks.rs#L60)

### `Marmot::get_blocked_users`

**Current.**

```rust
pub fn get_blocked_users( &self, account_ref: String, ) -> Result<Vec<BlockedUserFfi>, MarmotKitError>
```

Read the current blocked-user collection.

[Source](src/commands/user_blocks.rs#L70)

### `Marmot::is_user_blocked`

**Current.**

```rust
pub fn is_user_blocked( &self, account_ref: String, user_account_id_hex: String, ) -> Result<bool, MarmotKitError>
```

Check one user block.

[Source](src/commands/user_blocks.rs#L81)

### `Marmot::subscribe_blocked_users`

**Current.**

```rust
pub fn subscribe_blocked_users( &self, account_ref: String, ) -> Result<Arc<BlockListSubscription>, MarmotKitError>
```

Observe block-list snapshots.

[Source](src/commands/user_blocks.rs#L90)

</details>

<details>
<summary>conversions/attachment_history.rs</summary>

### `AttachmentHistoryVersion::change_since`

**Current.**

```rust
pub fn change_since( &self, previous: Arc<AttachmentHistoryVersion>, ) -> AttachmentHistoryChangeFfi
```

Compare current with an older version, including after the last page. RestartRequired means discard all loaded rows before restarting at the head.

[Source](src/conversions/attachment_history.rs#L24)

</details>

<details>
<summary>external_signer.rs</summary>

### `ExternalAccountSignerFfi::public_key`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
fn public_key(&self) -> Result<String, MarmotKitError>
```

Return the signer account public key as hex or npub.

[Source](src/external_signer.rs#L16)

### `ExternalAccountSignerFfi::sign_event`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
fn sign_event(&self, unsigned_event_json: String) -> Result<String, MarmotKitError>
```

Sign a serialized unsigned Nostr event and return the signed event JSON.

[Source](src/external_signer.rs#L22)

### `ExternalAccountSignerFfi::nip04_encrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
fn nip04_encrypt(&self, public_key: String, content: String) -> Result<String, MarmotKitError>
```

NIP-04 encrypt/decrypt support for legacy Nostr surfaces.

[Source](src/external_signer.rs#L28)

### `ExternalAccountSignerFfi::nip04_decrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
fn nip04_decrypt( &self, public_key: String, encrypted_content: String, ) -> Result<String, MarmotKitError>
```

Host callback for legacy NIP-04 decryption; return an unsupported error if not implemented.

[Source](src/external_signer.rs#L29)

### `ExternalAccountSignerFfi::nip44_encrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
fn nip44_encrypt(&self, public_key: String, content: String) -> Result<String, MarmotKitError>
```

NIP-44 encrypt/decrypt support for gift-wrap and encrypted app data.

[Source](src/external_signer.rs#L36)

### `ExternalAccountSignerFfi::nip44_decrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

```rust
fn nip44_decrypt(&self, public_key: String, payload: String) -> Result<String, MarmotKitError>
```

Host callback for NIP-44 payload decryption.

[Source](src/external_signer.rs#L37)

</details>

<details>
<summary>lib.rs</summary>

### `Marmot::new_with_configuration`

**Current.**

```rust
pub fn new_with_configuration( root_path: String, relay_urls: Vec<String>, options: MarmotOptions, ) -> Result<Arc<Self>, MarmotKitError>
```

Open with any combination of runtime options. Existing constructors are compatibility wrappers around this entry point.

[Source](src/lib.rs#L241)

### `Marmot::new_with_options`

**Compatibility.** Prefer new_with_configuration when combining settings.

```rust
pub fn new_with_options( root_path: String, relay_urls: Vec<String>, relay_policy: RelayPolicyFfi, secret_store: Option<Arc<dyn SecretStore>>, ) -> Result<Arc<Self>, MarmotKitError>
```

Open with an explicit relay policy and optional host-owned key storage. Existing constructors retain their public-only relay policy.

[Source](src/lib.rs#L257)

### `Marmot::new`

**Current.**

```rust
pub fn new(root_path: String, relay_urls: Vec<String>) -> Result<Arc<Self>, MarmotKitError>
```

Open the Marmot app at `root_path`, configured with the given default relay URLs. Account secrets (Nostr private keys) are stored in the platform keyring (Keychain on Apple platforms, Android's native keyring on Android) via the default keychain-backed account home — not in a plaintext file. Fallible because initializing the platform secret store can fail or another process may own the same root (`MarmotKitError::RuntimeBusy`). Root ownership is nonblocking and remains held until the final `Marmot`/runtime handle is dropped, even after `Marmot::shutdown`. Call `Marmot::start` before subscribing to events.

[Source](src/lib.rs#L285)

### `Marmot::new_with_secret_store`

**Compatibility.** Prefer new_with_configuration when combining settings.

```rust
pub fn new_with_secret_store( root_path: String, relay_urls: Vec<String>, secret_store: Arc<dyn SecretStore>, ) -> Result<Arc<Self>, MarmotKitError>
```

Open the Marmot app with host-supplied account-secret storage instead of the platform keychain. Identical to `Marmot::new` except that every read, write, and removal of an account signing key goes through `secret_store`.

[Source](src/lib.rs#L303)

### `Marmot::new_with_cursor_persistence`

**Compatibility.** Prefer new_with_configuration when combining settings.

```rust
pub fn new_with_cursor_persistence( root_path: String, relay_urls: Vec<String>, cursor_persistence: CursorPersistenceFfi, ) -> Result<Arc<Self>, MarmotKitError>
```

Construct with explicit advancing/frozen relay cursor behavior; new_with_configuration composes this with other options.

[Source](src/lib.rs#L333)

### `Marmot::new_with_client_name`

**Compatibility.** Prefer new_with_configuration when combining settings.

```rust
pub fn new_with_client_name( root_path: String, relay_urls: Vec<String>, client_name: Option<String>, cursor_persistence: CursorPersistenceFfi, secret_store: Option<Arc<dyn SecretStore>>, ) -> Result<Arc<Self>, MarmotKitError>
```

Open with an optional public client label for new KeyPackage publications. Existing constructors remain untagged. Whitespace-only labels are omitted. Hosts must supply this on every foreground/background runtime construction.

[Source](src/lib.rs#L352)

### `Marmot::start`

**Current.**

```rust
pub async fn start(&self) -> Result<(), MarmotKitError>
```

Bring the runtime to local readiness.

[Source](src/lib.rs#L389)

### `Marmot::shutdown`

**Current.**

```rust
pub async fn shutdown(&self)
```

Tear the runtime down. Drops all subscriptions; long-lived `EventsSubscription` / `ChatsSubscription` / etc. instances on the host side will see their `next()` return `None` shortly after.

[Source](src/lib.rs#L401)

### `Marmot::shutdown_and_close`

**Current.**

```rust
pub async fn shutdown_and_close(&self) -> Result<(), MarmotKitError>
```

Terminally stop work, close storage and release root ownership; reconstruct before further reads/work.

[Source](src/lib.rs#L436)

### `Marmot::storage_is_closed`

**Current.**

```rust
pub fn storage_is_closed(&self) -> bool
```

True once `Marmot::shutdown_and_close` has closed the store. A host can check this to confirm it is safe to be suspended, or to notice it is holding a spent handle and needs a fresh one.

[Source](src/lib.rs#L444)

### `Marmot::is_stopping`

**Current.**

```rust
pub fn is_stopping(&self) -> bool
```

True once shutdown has started. Host apps can use this to avoid launching more subscriptions or account work while they are moving to the background.

[Source](src/lib.rs#L451)

</details>

<details>
<summary>publisher.rs</summary>

### `Marmot::open_agent_publisher`

**Current.**

```rust
pub async fn open_agent_publisher( &self, account_ref: String, group_id_hex: String, options: PublisherOptionsFfi, ) -> Result<Arc<AgentTextPublisher>, MarmotKitError>
```

Publish a new stream start and return a handle for appending records. No exporter secret or framing state crosses the foreign boundary.

[Source](src/publisher.rs#L50)

### `AgentTextPublisher::info`

**Current.**

```rust
pub fn info(&self) -> PublisherInfoFfi
```

Read the anchored stream information.

[Source](src/publisher.rs#L84)

### `AgentTextPublisher::append`

**Current.**

```rust
pub async fn append( &self, kind: PublisherRecordFfi, text: String, ) -> Result<PublisherAckFfi, MarmotKitError>
```

Append transcript/preview content; transport failure does not discard accepted transcript content.

[Source](src/publisher.rs#L91)

### `AgentTextPublisher::finish`

**Current.**

```rust
pub async fn finish(&self) -> Result<SendSummaryFfi, MarmotKitError>
```

Seal and durably send the transcript; inspect send disposition. Retry on the same handle after failure; successful repeats return the original receipt.

[Source](src/publisher.rs#L108)

### `AgentTextPublisher::cancel`

**Current.**

```rust
pub async fn cancel(&self)
```

Stop the preview; an already-running finish wins. State is not restored after process restart.

[Source](src/publisher.rs#L112)

</details>

<details>
<summary>secret_store.rs</summary>

### `SecretStore::has_secret_for_label`

**Host callback.**

```rust
fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError>
```

Whether a credential is stored under `label`.

[Source](src/secret_store.rs#L33)

### `SecretStore::has_secret_for_account_id`

**Host callback.**

```rust
fn has_secret_for_account_id(&self, account_id_hex: String) -> Result<bool, MarmotKitError>
```

Whether a credential is stored under `account_id_hex`. Stores that key one credential per label report `false`.

[Source](src/secret_store.rs#L37)

### `SecretStore::write_secret`

**Host callback.**

```rust
fn write_secret( &self, label: String, account_id_hex: String, secret_key_hex: String, ) -> Result<(), MarmotKitError>
```

Persist `secret_key_hex` for this account, replacing any existing credential.

[Source](src/secret_store.rs#L41)

### `SecretStore::load_secret`

**Host callback.**

```rust
fn load_secret(&self, label: String, account_id_hex: String) -> Result<String, MarmotKitError>
```

Return the stored secret-key hex, or `MarmotKitError::SecretNotFound` when this account has no credential.

[Source](src/secret_store.rs#L50)

### `SecretStore::remove_secret`

**Host callback.**

```rust
fn remove_secret(&self, label: String, account_id_hex: String) -> Result<(), MarmotKitError>
```

Remove this account's credential. Removing a missing credential succeeds.

[Source](src/secret_store.rs#L54)

</details>

<details>
<summary>subscriptions/chat_window.rs</summary>

### `ChatListWindowSubscription::snapshot`

**Current.**

```rust
pub fn snapshot(&self) -> Option<ChatListWindowSnapshotFfi>
```

Take the initial complete replacement once, before driving next().

[Source](src/subscriptions/chat_window.rs#L29)

### `ChatListWindowSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Result<Option<ChatListWindowSnapshotFfi>, MarmotKitError>
```

One receiver per handle. Cancellation does not consume an update.

[Source](src/subscriptions/chat_window.rs#L33)

### `ChatListWindowSubscription::page`

**Current.**

```rust
pub async fn page( &self, sequence: u64, direction: ChatListPageDirectionFfi, count: u32, ) -> Result<ChatListWindowSnapshotFfi, MarmotKitError>
```

1–100 rows, at most 200 retained. Uses the installed snapshot's sequence. This can run while next() waits; accepted commands survive caller cancellation.

[Source](src/subscriptions/chat_window.rs#L38)

### `ChatListWindowSubscription::set_visible_anchor`

**Current.**

```rust
pub async fn set_visible_anchor( &self, sequence: u64, group_id_hex: String, ) -> Result<ChatListWindowSnapshotFfi, MarmotKitError>
```

Stable row identity, not pixel offset. A missing/outside anchor is rejected.

[Source](src/subscriptions/chat_window.rs#L51)

### `ChatListWindowSubscription::return_to_top`

**Current.**

```rust
pub async fn return_to_top( &self, sequence: u64, ) -> Result<ChatListWindowSnapshotFfi, MarmotKitError>
```

Navigate the prepared chat list back to its current head with sequence validation.

[Source](src/subscriptions/chat_window.rs#L62)

### `AccountAttentionSubscription::snapshot`

**Current.**

```rust
pub fn snapshot(&self) -> Option<AccountAttentionSnapshotFfi>
```

Take the initial account set once. Unavailable entries never contain invented totals.

[Source](src/subscriptions/chat_window.rs#L88)

### `AccountAttentionSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Result<Option<AccountAttentionSnapshotFfi>, MarmotKitError>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions/chat_window.rs#L91)

</details>

<details>
<summary>subscriptions/conversation_window.rs</summary>

### `ConversationWindowSubscription::snapshot`

**Current.**

```rust
pub fn snapshot(&self) -> Option<ConversationWindowSnapshotFfi>
```

Take once before next(). Complete replacements include every visible identity.

[Source](src/subscriptions/conversation_window.rs#L91)

### `ConversationWindowSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Result<Option<ConversationWindowSnapshotFfi>, MarmotKitError>
```

One receiver; cancellation leaves pending replacements available. Worker replacement is terminal: reopen the conversation after Closed/None with a fresh generation.

[Source](src/subscriptions/conversation_window.rs#L96)

### `ConversationWindowSubscription::cancel`

**Current.**

```rust
pub async fn cancel(&self)
```

Wake receivers/commands and release the retained runtime window. Idempotent. Drop the native object too when finished. Previously returned snapshots stay valid.

[Source](src/subscriptions/conversation_window.rs#L115)

### `ConversationWindowSubscription::page`

**Current.**

```rust
pub async fn page( &self, revision: ConversationWindowRevisionFfi, direction: ConversationPageDirectionFfi, count: u32, timeout_ms: u32, ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError>
```

1–200 rows, at most 200 retained; report a new visible anchor to page beyond saturated context. Zero timeout uses 30 seconds. After timeout/cancellation an accepted command may still complete through next(); refresh before retrying.

[Source](src/subscriptions/conversation_window.rs#L127)

### `ConversationWindowSubscription::set_visible_anchor`

**Current.**

```rust
pub async fn set_visible_anchor( &self, revision: ConversationWindowRevisionFfi, message_id_hex: String, timeout_ms: u32, ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError>
```

Report a row in the installed replacement, not a pixel offset. No read acknowledgement.

[Source](src/subscriptions/conversation_window.rs#L146)

### `ConversationWindowSubscription::return_to_latest`

**Current.**

```rust
pub async fn return_to_latest( &self, revision: ConversationWindowRevisionFfi, timeout_ms: u32, ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError>
```

Resume following new arrivals. Retains the current row budget (up to 200).

[Source](src/subscriptions/conversation_window.rs#L159)

### `ConversationWindowSubscription::jump_to_message`

**Current.**

```rust
pub async fn jump_to_message( &self, revision: ConversationWindowRevisionFfi, message_id_hex: String, timeout_ms: u32, ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError>
```

Missing targets fail explicitly. Commands may run while next() waits.

[Source](src/subscriptions/conversation_window.rs#L169)

</details>

<details>
<summary>subscriptions.rs</summary>

### `ChatsSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub fn snapshot(&self) -> Vec<AppGroupRecordFfi>
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/subscriptions.rs#L57)

### `ChatsSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next(&self) -> Option<AppGroupRecordFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L61)

### `ChatListSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub fn snapshot(&self) -> Vec<ChatListRowFfi>
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/subscriptions.rs#L96)

### `ChatListSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next(&self) -> Option<ChatListRowFfi>
```

Legacy row-only update stream.

[Source](src/subscriptions.rs#L110)

### `ChatListSubscription::next_update`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next_update(&self) -> Option<ChatListSubscriptionUpdateFfi>
```

Typed update stream, including atomic full-list replacement snapshots.

[Source](src/subscriptions.rs#L134)

### `MessagesSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub fn snapshot(&self) -> Vec<AppMessageRecordFfi>
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/subscriptions.rs#L161)

### `MessagesSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next(&self) -> Option<MessageUpdateFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L165)

### `TimelineMessagesSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub fn snapshot(&self) -> Option<TimelinePageFfi>
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/subscriptions.rs#L255)

### `TimelineMessagesSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next(&self) -> Option<TimelinePageFfi>
```

Await the next live update and return the resulting authoritative window. Windowing (ordering, dedup, head-anchoring while scrolled back, and the cap) is owned by the runtime, so this returns exactly the bounded window pagination operates on — render it directly. Use `next_update`(Self::next_update) instead to receive the raw delta.

[Source](src/subscriptions.rs#L264)

### `TimelineMessagesSubscription::next_update`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next_update(&self) -> Option<TimelineSubscriptionUpdateFfi>
```

Consume raw timeline deltas or a replacement page. Use either next or next_update, not both; the host maintains delta ordering and bounds.

[Source](src/subscriptions.rs#L273)

### `TimelineMessagesSubscription::paginate_backwards`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn paginate_backwards(&self, count: u32) -> Result<TimelinePageFfi, MarmotKitError>
```

Extend the materialized window toward older history by up to `count` messages and return the new window. The returned page is already sorted, deduplicated, capped, and carries correct `has_more_before` / `has_more_after` flags — render it directly; no client-side merging or windowing is required. The store read runs off the caller thread and uses a different lock than `next()`, so a host driving `next()` on a background task can paginate without blocking (and this never blocks the UI thread, unlike the synchronous `Marmot::timeline_messages`).

[Source](src/subscriptions.rs#L286)

### `TimelineMessagesSubscription::paginate_forwards`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn paginate_forwards(&self, count: u32) -> Result<TimelinePageFfi, MarmotKitError>
```

Extend the materialized window toward the live head by up to `count` messages and return the new window. Reaching the head re-anchors the window (`has_more_after` becomes false). Same windowing/threading guarantees as `paginate_backwards`(Self::paginate_backwards).

[Source](src/subscriptions.rs#L295)

### `GroupStateSubscription::snapshot`

**Current.**

```rust
pub fn snapshot(&self) -> Option<AppGroupRecordFfi>
```

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

[Source](src/subscriptions.rs#L319)

### `GroupStateSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Option<AppGroupRecordFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L323)

### `EventsSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Option<MarmotEventFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L348)

### `NotificationsSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Option<NotificationUpdateFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L369)

### `UserSearchSubscription::next_update`

**Current.**

```rust
pub async fn next_update(&self) -> Option<UserSearchUpdateFfi>
```

Await the next step of the search, or `None` once it is over.

[Source](src/subscriptions.rs#L427)

### `AgentStreamSubscription::stream_id_hex`

**Current.**

```rust
pub fn stream_id_hex(&self) -> String
```

The resolved stream id this watch is following (hex).

[Source](src/subscriptions.rs#L436)

### `AgentStreamSubscription::next`

**Current.**

```rust
pub async fn next(&self) -> Option<AgentStreamUpdateFfi>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L440)

### `PresentedChatListSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub fn snapshot(&self) -> Option<crate::conversions::PresentedChatListUpdateFfi>
```

Take the initial snapshot once, with generation and sequence zero.

[Source](src/subscriptions.rs#L473)

### `PresentedChatListSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

```rust
pub async fn next( &self, ) -> Result<Option<crate::conversions::PresentedChatListUpdateFfi>, MarmotKitError>
```

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

[Source](src/subscriptions.rs#L476)

</details>

<details>
<summary>Host-managed automatic attachment acquisition</summary>

### `Marmot::begin_attachment_permission_update`

```rust
pub async fn begin_attachment_permission_update( &self, account_ref: String, ) -> Result<String, MarmotKitError>
```

Revoke automatic permission for this account before asynchronous network/preference evaluation. Returns a single-use runtime/account generation. Requires HostManaged construction; do not persist the token or mint a new one from a stale callback. See the [host-managed contract](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

[Source](src/commands/attachment_controls.rs#L28)

### `Marmot::request_automatic_attachment`

```rust
pub async fn request_automatic_attachment( &self, account_ref: String, group_id_hex: String, target: AttachmentLocalTargetFfi, ) -> Result<AutomaticAttachmentRequestFfi, MarmotKitError>
```

Submit idempotent automatic demand for an authoritative original source slot. Returns current status plus whether work was newly queued; preserves suppression, history, deadlines and retry budgets. Use from foreground and restored workers; never substitute explicit download-again or legacy downloadMedia after a local miss. See [Android migration](ATTACHMENT-ACCESS.md#android-migration).

[Source](src/commands/attachment_controls.rs#L50)

### `Marmot::set_attachment_automatic_permission`

```rust
pub async fn set_attachment_automatic_permission( &self, account_ref: String, generation: String, permission: AttachmentAutomaticPermissionFfi, ) -> Result<bool, MarmotKitError>
```

Apply media-category permission using the generation captured before evaluating host policy. False means stale, foreign or already consumed; it is not permission to retry with a fresh token. Approval is runtime-only and cannot override the durable automatic policy. See the [permission lifecycle](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

[Source](src/commands/attachment_controls.rs#L38)

</details>

<details>
<summary>Durable local sends and caller correlation</summary>

### `Marmot::local_send_status`

```rust
pub fn local_send_status( &self, account_ref: String, group_id_hex: String, client_token: String, ) -> Result<Option<LocalSendStatusFfi>, MarmotKitError>
```

Read a retained submission's local state without relay I/O. `None` means no retained
association. `Completed` describes the worker attempt; inspect its summary disposition
and follow timeline updates for later delivery. See [local sends](LOCAL-SENDS.md).

[Source](src/commands/local_submissions.rs#L125)

### `Marmot::reply_to_message_with_client_token`

```rust
pub async fn reply_to_message_with_client_token( &self, account_ref: String, group_id_hex: String, target_message_id: String, text: String, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>
```

Durably admit a reply and bind its optimistic bubble to an opaque local token.
Returns local acceptance before relay publication. Repeating the original request
and token returns the same identity; changed requests are rejected. See [local sends](LOCAL-SENDS.md).

[Source](src/commands/local_submissions.rs#L57)

### `Marmot::send_message_draft_with_client_token`

```rust
pub async fn send_message_draft_with_client_token( &self, account_ref: String, revision: Arc<MessageDraftRevisionFfi>, attachments: Vec<MediaAttachmentReferenceFfi>, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>
```

Atomically consume exactly the supplied draft revision and retain its token-bound
message. Prepared attachments must match selected descriptors. Returns local
acceptance, not delivery; never clear a newer composer on completion. See [local sends](LOCAL-SENDS.md).

[Source](src/commands/local_submissions.rs#L79)

### `Marmot::send_text_with_client_token`

```rust
pub async fn send_text_with_client_token( &self, account_ref: String, group_id_hex: String, text: String, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>
```

Admit text durably outside the account publication queue. Use one token per logical
submission and reconcile by the exact token on timeline rows. Acceptance survives
caller cancellation and restart; delivery uses ordinary subscriptions. See [local sends](LOCAL-SENDS.md).

[Source](src/commands/local_submissions.rs#L37)

### `Marmot::upload_media_with_client_token`

```rust
pub async fn upload_media_with_client_token( &self, account_ref: String, group_id_hex: String, request: MediaUploadRequestFfi, client_token: String, ) -> Result<MediaUploadSubmissionFfi, MarmotKitError>
```

Upload encrypted attachments and optionally admit the resulting token-bound message.
The result includes uploaded references and optional local acceptance. Uploads themselves
are not idempotent or restart-resumable; query token status after unknown outcomes.
See [local sends](LOCAL-SENDS.md) for cancellation and epoch-bound media handling.

[Source](src/commands/local_submissions.rs#L101)

</details>

<details>
<summary>Stateless public-event verification</summary>

### `verify_bip340_signature`

```rust
pub fn verify_bip340_signature( public_key_hex: String, message_hex: String, signature_hex: String, ) -> bool
```

Verify a BIP-340 Schnorr signature over a caller-computed 32-byte digest using
MDK's Nostr/libsecp256k1 stack. This stateless helper needs no `Marmot` object,
account, relay connection, or secret key. The arguments are hex-encoded x-only
public key, digest, and signature; malformed values or verification failure
return `false`. Prefer full-event verification below when an event JSON body is
available, because this helper does not check a Nostr event's canonical ID.

[Source](src/commands/nostr_verification.rs#L6)

### `verify_public_nostr_event_json`

```rust
pub fn verify_public_nostr_event_json(event_json: String) -> bool
```

Verify both the canonical ID and BIP-340 signature of a public Nostr event.
This stateless helper needs no `Marmot` object or account and returns `false`
for malformed JSON or failed verification. It does not establish an allowed
author, kind, tag, relay provenance, or MLS group-membership policy; the host
must enforce those separately and bound any untrusted JSON before passing it.

[Source](src/commands/nostr_verification.rs#L18)

</details>
