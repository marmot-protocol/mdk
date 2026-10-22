//! Deployment choices a host makes for its users: which services they rely on.
//!
//! MDK serves any Marmot client, so these are configuration, not protocol.
//! [`MarmotDeployment::white_noise`] is White Noise's deployment and keeps its
//! behaviour exactly. [`MarmotDeployment::neutral`] configures none of them.
//! See `docs/marmot-architecture/review/brief-host-configuration.md`.

pub use nostr_directory::config::{KeyPackageClientPreference, OpenRankingProvider};

/// The services and identifiers one deployment's users rely on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotDeployment {
    /// Relays this deployment operates. A route's history certifies once its
    /// operated relays finish an untruncated comparison; every other relay on
    /// the route is best effort and never blocks completion. A route with no
    /// operated relay requires all of its relays. The raw strings feed the
    /// recovery route-policy hash, so a change rebuilds pending scopes.
    pub recovery_operated_relays: Vec<String>,
    /// Public relays onboarding and account setup also search for an account's
    /// relay list and profile, besides the discovery relays the host passes.
    /// They are never adopted as the account's messaging relays.
    pub discovery_indexer_relays: Vec<String>,
    /// Blossom servers signed into a new group's encrypted-media component.
    /// Each must accept opaque `application/octet-stream` blobs: encrypted
    /// media is indistinguishable from random bytes.
    pub new_group_media_endpoints: Vec<String>,
    /// Blossom server for encrypted group images. Group state records no
    /// server, so every client sharing a group must use the same one.
    pub group_image_endpoint: Option<String>,
    /// Public profile-image upload server. The resulting URL is published in
    /// kind:0 metadata. Peers' avatars load from that URL, never from here.
    pub profile_image_endpoint: Option<String>,
    /// Optional Open Ranking discovery tier for directory search.
    pub open_ranking: Option<OpenRankingProvider>,
    /// How KeyPackage candidates rank by their self-asserted `client` tag.
    pub key_package_client_preference: KeyPackageClientPreference,
    /// NIP-32 namespace of the origin label on moderation reports. The
    /// operator's report parser matches it. Reporting refuses a destination
    /// while this is unset.
    pub moderation_label_namespace: Option<String>,
    /// Platform keychain service name for account secrets. Changing it for an
    /// existing install strands the secrets stored under the old name.
    pub keychain_service: String,
}

/// Neutral keychain service name for hosts that never chose one.
pub const NEUTRAL_KEYCHAIN_SERVICE_NAME: &str = "org.marmot-protocol.mdk";

/// White Noise's values. Each is defined once, here.
mod white_noise {
    pub(super) const OPERATED_RELAYS: &[&str] = &[
        "wss://relay.eu.whitenoise.chat",
        "wss://relay.us.whitenoise.chat",
    ];
    pub(super) const VERTEX_RELAY: &str = "wss://relay.vertexlab.io";
    pub(super) const DISCOVERY_INDEXERS: &[&str] = &[
        "wss://purplepag.es",
        VERTEX_RELAY,
        "wss://nos.lol",
        "wss://relay.ditto.pub",
        "wss://relay.primal.net",
    ];
    pub(super) const MEDIA_SERVERS: &[&str] = &[
        "https://blossom.divine.video",
        "https://blossom.ditto.pub",
        "https://cdn.hzrd149.com",
    ];
    pub(super) const PROFILE_IMAGE_SERVER: &str = "https://blossom.primal.net";
    pub(super) const OPEN_RANKING_SEARCH: &str = "https://ranking.vertexlab.io/search/pubkeys";
    pub(super) const PREFERRED_CLIENTS: &[&str] = &["whitenoise"];
    pub(super) const LAST_CLIENTS: &[&str] = &["amethyst"];
    pub(super) const MODERATION_LABEL_NAMESPACE: &str = "chat.whitenoise.report";
    pub(super) const KEYCHAIN_SERVICE: &str = "com.marmot.whitenoise";
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

impl MarmotDeployment {
    /// No deployment services: every list empty, every option unset, and the
    /// neutral keychain service name.
    pub fn neutral() -> Self {
        Self {
            recovery_operated_relays: Vec::new(),
            discovery_indexer_relays: Vec::new(),
            new_group_media_endpoints: Vec::new(),
            group_image_endpoint: None,
            profile_image_endpoint: None,
            open_ranking: None,
            key_package_client_preference: KeyPackageClientPreference::default(),
            moderation_label_namespace: None,
            keychain_service: NEUTRAL_KEYCHAIN_SERVICE_NAME.to_owned(),
        }
    }

    /// White Noise's deployment, byte for byte what MDK compiled in before
    /// these became configuration.
    pub fn white_noise() -> Self {
        Self {
            recovery_operated_relays: owned(white_noise::OPERATED_RELAYS),
            discovery_indexer_relays: owned(white_noise::DISCOVERY_INDEXERS),
            new_group_media_endpoints: owned(white_noise::MEDIA_SERVERS),
            group_image_endpoint: Some(white_noise::MEDIA_SERVERS[0].to_owned()),
            profile_image_endpoint: Some(white_noise::PROFILE_IMAGE_SERVER.to_owned()),
            open_ranking: Some(OpenRankingProvider {
                search_endpoint: white_noise::OPEN_RANKING_SEARCH.to_owned(),
                profile_relays: vec![white_noise::VERTEX_RELAY.to_owned()],
            }),
            key_package_client_preference: KeyPackageClientPreference {
                preferred: owned(white_noise::PREFERRED_CLIENTS),
                last: owned(white_noise::LAST_CLIENTS),
            },
            moderation_label_namespace: Some(white_noise::MODERATION_LABEL_NAMESPACE.to_owned()),
            keychain_service: white_noise::KEYCHAIN_SERVICE.to_owned(),
        }
    }

    /// Trim every value and drop empty entries, so blank configuration means
    /// unset. An Open Ranking provider with no profile relay is disabled.
    pub fn normalize(mut self) -> Self {
        self.recovery_operated_relays = normalize_list(self.recovery_operated_relays);
        self.discovery_indexer_relays = normalize_list(self.discovery_indexer_relays);
        self.new_group_media_endpoints = normalize_list(self.new_group_media_endpoints);
        self.group_image_endpoint = trim_optional(self.group_image_endpoint);
        self.profile_image_endpoint = trim_optional(self.profile_image_endpoint);
        self.open_ranking = self.open_ranking.and_then(|provider| {
            let search_endpoint = provider.search_endpoint.trim().to_owned();
            let profile_relays = normalize_list(provider.profile_relays);
            (!search_endpoint.is_empty() && !profile_relays.is_empty()).then_some(
                OpenRankingProvider {
                    search_endpoint,
                    profile_relays,
                },
            )
        });
        self.key_package_client_preference.preferred =
            normalize_list(self.key_package_client_preference.preferred);
        self.key_package_client_preference.last =
            normalize_list(self.key_package_client_preference.last);
        self.moderation_label_namespace = trim_optional(self.moderation_label_namespace);
        self.keychain_service = match self.keychain_service.trim() {
            "" => NEUTRAL_KEYCHAIN_SERVICE_NAME.to_owned(),
            name => name.to_owned(),
        };
        self
    }

    /// [`Self::discovery_indexer_relays`] as transport endpoints.
    pub(crate) fn discovery_indexer_endpoints(&self) -> Vec<cgka_traits::TransportEndpoint> {
        self.discovery_indexer_relays
            .iter()
            .cloned()
            .map(cgka_traits::TransportEndpoint)
            .collect()
    }

    /// The group-image server for `requested`, else this deployment's. With
    /// neither, group images can't be uploaded or fetched: group state
    /// records no server, so there is nowhere to look.
    pub(crate) fn group_image_endpoint_for(
        &self,
        requested: Option<&str>,
    ) -> Result<String, crate::AppError> {
        requested
            .or(self.group_image_endpoint.as_deref())
            .map(str::to_owned)
            .ok_or_else(|| {
                crate::AppError::BlobStore("this deployment sets no group-image server".into())
            })
    }

    /// The profile-image upload server for `requested`, else this
    /// deployment's. With neither there is no upload; peers' avatars still
    /// load from the URL in their own profile.
    pub(crate) fn profile_image_endpoint_for(
        &self,
        requested: Option<&str>,
    ) -> Result<String, crate::AppError> {
        requested
            .or(self.profile_image_endpoint.as_deref())
            .map(str::to_owned)
            .ok_or_else(|| {
                crate::AppError::BlobStore("this deployment sets no profile-image server".into())
            })
    }
}

impl Default for MarmotDeployment {
    /// [`MarmotDeployment::neutral`]: a host names its services, White
    /// Noise's included ([`MarmotDeployment::white_noise`]).
    fn default() -> Self {
        Self::neutral()
    }
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = Vec::new();
    for value in values {
        let value = value.trim().to_owned();
        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preset must keep White Noise's behaviour: these are the values MDK
    /// compiled in before they became configuration. The recovery set's raw
    /// strings feed the route-policy hash, so any drift there would rebuild
    /// every pending recovery scope.
    #[test]
    fn white_noise_preset_keeps_the_values_mdk_compiled_in() {
        let deployment = MarmotDeployment::white_noise();
        assert_eq!(
            deployment.recovery_operated_relays,
            [
                "wss://relay.eu.whitenoise.chat",
                "wss://relay.us.whitenoise.chat"
            ]
        );
        assert_eq!(
            deployment.discovery_indexer_relays,
            [
                "wss://purplepag.es",
                "wss://relay.vertexlab.io",
                "wss://nos.lol",
                "wss://relay.ditto.pub",
                "wss://relay.primal.net",
            ]
        );
        assert_eq!(
            deployment.new_group_media_endpoints,
            [
                "https://blossom.divine.video",
                "https://blossom.ditto.pub",
                "https://cdn.hzrd149.com",
            ]
        );
        assert_eq!(
            deployment.group_image_endpoint.as_deref(),
            Some("https://blossom.divine.video")
        );
        assert_eq!(
            deployment.profile_image_endpoint.as_deref(),
            Some("https://blossom.primal.net")
        );
        assert_eq!(
            deployment.open_ranking,
            Some(OpenRankingProvider {
                search_endpoint: "https://ranking.vertexlab.io/search/pubkeys".into(),
                profile_relays: vec!["wss://relay.vertexlab.io".into()],
            })
        );
        assert_eq!(
            deployment.key_package_client_preference.preferred,
            ["whitenoise"]
        );
        assert_eq!(deployment.key_package_client_preference.last, ["amethyst"]);
        assert_eq!(
            deployment.moderation_label_namespace.as_deref(),
            Some("chat.whitenoise.report")
        );
        assert_eq!(deployment.keychain_service, "com.marmot.whitenoise");
        assert_eq!(deployment.clone().normalize(), deployment);
    }

    #[test]
    fn neutral_configures_no_service() {
        let deployment = MarmotDeployment::neutral();
        assert!(deployment.recovery_operated_relays.is_empty());
        assert!(deployment.discovery_indexer_relays.is_empty());
        assert!(deployment.new_group_media_endpoints.is_empty());
        assert_eq!(deployment.group_image_endpoint, None);
        assert_eq!(deployment.profile_image_endpoint, None);
        assert_eq!(deployment.open_ranking, None);
        assert_eq!(
            deployment.key_package_client_preference,
            KeyPackageClientPreference::default()
        );
        assert_eq!(deployment.moderation_label_namespace, None);
        assert_eq!(deployment.keychain_service, NEUTRAL_KEYCHAIN_SERVICE_NAME);
    }

    #[test]
    fn normalize_treats_blank_values_as_unset() {
        let deployment = MarmotDeployment {
            discovery_indexer_relays: vec![" wss://a.example ".into(), "  ".into()],
            group_image_endpoint: Some("  ".into()),
            open_ranking: Some(OpenRankingProvider {
                search_endpoint: "https://rank.example".into(),
                profile_relays: vec![" ".into()],
            }),
            moderation_label_namespace: Some(" ns ".into()),
            ..MarmotDeployment::neutral()
        }
        .normalize();
        assert_eq!(deployment.discovery_indexer_relays, ["wss://a.example"]);
        assert_eq!(deployment.group_image_endpoint, None);
        assert_eq!(
            deployment.open_ranking, None,
            "no profile relay disables the tier"
        );
        assert_eq!(deployment.moderation_label_namespace.as_deref(), Some("ns"));
        let blank_keychain = MarmotDeployment {
            keychain_service: "  ".into(),
            ..MarmotDeployment::neutral()
        }
        .normalize();
        assert_eq!(
            blank_keychain.keychain_service,
            NEUTRAL_KEYCHAIN_SERVICE_NAME
        );
    }

    #[test]
    fn key_package_preference_ranks_by_client_tag() {
        let white_noise = MarmotDeployment::white_noise().key_package_client_preference;
        assert_eq!(white_noise.rank_for_test(Some("WhiteNoise")), 2);
        assert_eq!(white_noise.rank_for_test(Some(" amethyst ")), 0);
        assert_eq!(white_noise.rank_for_test(Some("other")), 1);
        assert_eq!(white_noise.rank_for_test(None), 1);
        let neutral = KeyPackageClientPreference::default();
        assert_eq!(neutral.rank_for_test(Some("whitenoise")), 1);
        assert_eq!(neutral.rank_for_test(Some("amethyst")), 1);
    }

    #[test]
    fn unset_image_servers_are_refused_not_borrowed() {
        let neutral = MarmotDeployment::neutral();
        assert!(neutral.group_image_endpoint_for(None).is_err());
        assert!(neutral.profile_image_endpoint_for(None).is_err());
        assert_eq!(
            neutral
                .group_image_endpoint_for(Some("https://other.example"))
                .unwrap(),
            "https://other.example",
            "an explicit server still wins"
        );
        let white_noise = MarmotDeployment::white_noise();
        assert_eq!(
            white_noise.group_image_endpoint_for(None).unwrap(),
            "https://blossom.divine.video"
        );
        assert_eq!(
            white_noise.profile_image_endpoint_for(None).unwrap(),
            "https://blossom.primal.net"
        );
    }
}
