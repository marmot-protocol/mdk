//! Directory, identity-resolution, profile, and Markdown-preview commands.

use crate::conversions::{UserProfileMetadataFfi, normalize_member_ref_ffi};
use crate::errors::MarmotKitError;
use crate::markdown::{self, MarkdownDocumentFfi};
use crate::{Marmot, endpoints};

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Best-effort cached display name for an account id. Returns the Nostr
    /// kind:0 display_name/name when the runtime has projected one, or the
    /// local account label if the id refers to one of our own accounts.
    /// `None` when nothing is known yet — call `refresh_directory` to fetch.
    pub fn display_name(&self, account_id_hex: String) -> Option<String> {
        self.runtime.display_name_for_account_id(&account_id_hex)
    }

    /// Convert a hex account id (Nostr public key) into its `npub…` bech32
    /// form for display. `None` if the hex isn't a valid public key.
    pub fn npub(&self, account_id_hex: String) -> Option<String> {
        marmot_app::npub_for_account_id(&account_id_hex).ok()
    }

    /// Normalize a public-key reference (npub or hex) to canonical hex.
    /// `None` if it isn't a valid public key. Used to resolve a scanned or
    /// deep-linked npub back to the account id the rest of the API expects.
    pub fn account_id_hex(&self, reference: String) -> Option<String> {
        normalize_member_ref_ffi(&reference)
            .ok()
            .map(|normalized| normalized.account_id_hex)
    }

    /// Parse plaintext message content into the same Markdown AST returned on
    /// message and timeline records. Useful for draft previews and host-side
    /// fallback rendering.
    pub fn parse_markdown(&self, text: String) -> MarkdownDocumentFfi {
        markdown::parse_markdown_document(&text)
    }

    /// Full cached Nostr kind:0 profile for an account id (name, display
    /// name, about, picture, nip05, lud16), if the runtime has one
    /// projected. The local account's own profile is cached immediately
    /// after `publish_user_profile`; other accounts' profiles populate via
    /// `refresh_directory`. Returns `None` when nothing is cached yet.
    pub fn user_profile(
        &self,
        account_id_hex: String,
    ) -> Result<Option<UserProfileMetadataFfi>, MarmotKitError> {
        let entry = self.app.directory_entry_for_account_id(&account_id_hex)?;
        Ok(entry.and_then(|record| record.profile).map(Into::into))
    }

    /// Fetch and cache an account's own Nostr kind:0 profile from `relays`.
    /// After this resolves, `user_profile` / `display_name` return the
    /// freshly-fetched metadata (name, picture, etc.) for that account.
    pub async fn refresh_profile(
        &self,
        account_id_hex: String,
        relays: Vec<String>,
    ) -> Result<(), MarmotKitError> {
        self.app
            .refresh_profile_for_account_id(&account_id_hex, endpoints(&relays))
            .await?;
        Ok(())
    }
}
