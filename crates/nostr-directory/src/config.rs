//! The directory's settings. The host chooses them through its deployment and
//! app configuration.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use cgka_traits::TransportEndpoint;

/// Builds an HTTP client that honours the host's network proxy.
pub type HttpClientBuilder =
    fn(reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, &'static str>;

/// The directory's settings, as the app configured them.
#[derive(Clone, Debug)]
pub struct DirectoryConfig {
    /// Relays the host chose for directory reads. Empty means
    /// [`Self::default_relays`].
    pub directory_relays: Vec<TransportEndpoint>,
    /// The app's default relays.
    pub default_relays: Vec<TransportEndpoint>,
    /// How far past now an event's `created_at` may be and still count.
    pub max_future_skew: Duration,
    /// How KeyPackage candidates rank by their `client` tag.
    pub key_package_client_preference: KeyPackageClientPreference,
    /// The Open Ranking discovery tier for search, when the deployment has one.
    pub open_ranking: Option<OpenRankingProvider>,
    /// Accounts search starts from when the searcher's own web of trust is
    /// empty.
    pub fallback_seeds: Vec<String>,
    /// How Open Ranking builds its HTTP client.
    pub http_builder: HttpClientBuilder,
    /// Replaces the wall clock for freshness checks. Tests set it; the app
    /// passes `None`.
    pub test_clock: Option<Arc<AtomicU64>>,
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
    pub fn rank(&self, client: Option<&str>) -> u8 {
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
