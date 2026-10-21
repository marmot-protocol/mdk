//! The directory's settings. The host chooses them through its deployment and
//! app configuration.

use cgka_traits::TransportEndpoint;

/// The relays the directory reads from, as the app configured them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryConfig {
    /// Relays the host chose for directory reads. Empty means
    /// [`Self::default_relays`].
    pub directory_relays: Vec<TransportEndpoint>,
    /// The app's default relays.
    pub default_relays: Vec<TransportEndpoint>,
}

/// An Open Ranking pubkey-search endpoint and the relays that hydrate its
/// results into signed kind-0 profiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRankingProvider {
    pub search_endpoint: String,
    pub profile_relays: Vec<String>,
}

/// KeyPackage ranking by self-asserted `client` tag. Labels authenticate
/// nothing: they only order candidates that already passed admission.
/// Temporary until device-aware delivery replaces single-package selection
/// (mdk#1696).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPackageClientPreference {
    /// Client names ranked first, case-insensitively.
    pub preferred: Vec<String>,
    /// Client names ranked last, case-insensitively.
    pub last: Vec<String>,
}

impl KeyPackageClientPreference {
    /// 2 for a preferred client, 0 for one ranked last, 1 for any other or no
    /// tag.
    pub(crate) fn rank(&self, client: Option<&str>) -> u8 {
        let Some(client) = client.map(str::trim) else {
            return 1;
        };
        let matches = |names: &[String]| names.iter().any(|name| name.eq_ignore_ascii_case(client));
        if matches(&self.preferred) {
            2
        } else if matches(&self.last) {
            0
        } else {
            1
        }
    }
}
