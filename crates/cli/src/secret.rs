//! Stdin-imported Nostr secrets and NIP-46 bunker URIs: zeroizing storage and redacted diagnostics.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// An `nsec` (or compatible secret) read from stdin for account import.
///
/// Not `Clone`: move ownership through import paths instead of copying secrets.
pub(crate) struct ImportNsec(Zeroizing<String>);

impl ImportNsec {
    pub(crate) fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    pub(crate) fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for ImportNsec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportNsec(**redacted**)")
    }
}

impl Serialize for ImportNsec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ImportNsec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Zeroizing::new(String::deserialize(deserializer)?)))
    }
}

/// A NIP-46 `bunker://` URI read from stdin (may carry a `?secret=` token).
///
/// Not `Clone`: move ownership through login/register paths instead of copying secrets.
pub(crate) struct ImportBunkerUri(Zeroizing<String>);

impl ImportBunkerUri {
    pub(crate) fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    pub(crate) fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for ImportBunkerUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportBunkerUri(**redacted**)")
    }
}

impl Serialize for ImportBunkerUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ImportBunkerUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Zeroizing::new(String::deserialize(deserializer)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn import_nsec_debug_does_not_leak_secret() {
        let secret = ImportNsec::new(Zeroizing::new(
            "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99".to_owned(),
        ));
        let debug = format!("{secret:?}");
        assert!(!debug.contains("nsec1j4"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn import_bunker_uri_debug_does_not_leak_secret() {
        let uri = ImportBunkerUri::new(Zeroizing::new(
            "bunker://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?relay=wss%3A%2F%2Frelay.example&secret=top-secret-token"
                .to_owned(),
        ));
        let debug = format!("{uri:?}");
        assert!(!debug.contains("top-secret-token"));
        assert!(!debug.contains("bunker://"));
        assert!(debug.contains("redacted"));
    }
}
