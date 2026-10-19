//! The deployment record a host passes at construction. It mirrors
//! `marmot_app::MarmotDeployment`; see the host-configuration brief
//! (`docs/marmot-architecture/review/brief-host-configuration.md`).

use marmot_app::{KeyPackageClientPreference, MarmotDeployment, OpenRankingProvider};

/// An Open Ranking pubkey-search endpoint and the relays that hydrate its
/// results into signed kind-0 profiles. With no profile relay the tier is off.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OpenRankingProviderFfi {
    pub search_endpoint: String,
    pub profile_relays: Vec<String>,
}

/// The services and identifiers one deployment's users rely on. Start from
/// [`marmot_deployment_white_noise`] or [`marmot_deployment_neutral`] and
/// change what differs. Blank values count as unset.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MarmotDeploymentFfi {
    /// Relays this deployment operates. A route's history certifies once its
    /// operated relays finish a full comparison; a route with none requires
    /// all of its relays. Changing the set rebuilds pending recovery scopes.
    pub recovery_operated_relays: Vec<String>,
    /// Public relays onboarding and account setup also search for an
    /// account's relay list and profile. Never adopted as messaging relays.
    pub discovery_indexer_relays: Vec<String>,
    /// Blossom servers signed into a new group's encrypted-media component.
    /// Each must accept opaque `application/octet-stream` blobs.
    pub new_group_media_endpoints: Vec<String>,
    /// Blossom server for encrypted group images. Group state records no
    /// server, so every client sharing a group must use the same one.
    pub group_image_endpoint: Option<String>,
    /// Public profile-image upload server. Peers' avatars load from the URL
    /// in their own profile, never from here.
    pub profile_image_endpoint: Option<String>,
    /// Optional Open Ranking discovery tier for directory search.
    pub open_ranking: Option<OpenRankingProviderFfi>,
    /// KeyPackage `client` tags ranked first, case-insensitively.
    pub key_package_preferred_clients: Vec<String>,
    /// KeyPackage `client` tags ranked last, case-insensitively.
    pub key_package_last_clients: Vec<String>,
    /// NIP-32 namespace on moderation report labels. The operator's report
    /// parser matches it; reporting refuses a destination while it is unset.
    pub moderation_label_namespace: Option<String>,
    /// Platform keychain service for account secrets when no `SecretStore`
    /// is supplied. Changing it for an existing install strands the secrets
    /// stored under the old name.
    pub keychain_service: String,
}

impl From<MarmotDeployment> for MarmotDeploymentFfi {
    fn from(deployment: MarmotDeployment) -> Self {
        Self {
            recovery_operated_relays: deployment.recovery_operated_relays,
            discovery_indexer_relays: deployment.discovery_indexer_relays,
            new_group_media_endpoints: deployment.new_group_media_endpoints,
            group_image_endpoint: deployment.group_image_endpoint,
            profile_image_endpoint: deployment.profile_image_endpoint,
            open_ranking: deployment
                .open_ranking
                .map(|provider| OpenRankingProviderFfi {
                    search_endpoint: provider.search_endpoint,
                    profile_relays: provider.profile_relays,
                }),
            key_package_preferred_clients: deployment.key_package_client_preference.preferred,
            key_package_last_clients: deployment.key_package_client_preference.last,
            moderation_label_namespace: deployment.moderation_label_namespace,
            keychain_service: deployment.keychain_service,
        }
    }
}

impl From<MarmotDeploymentFfi> for MarmotDeployment {
    fn from(deployment: MarmotDeploymentFfi) -> Self {
        Self {
            recovery_operated_relays: deployment.recovery_operated_relays,
            discovery_indexer_relays: deployment.discovery_indexer_relays,
            new_group_media_endpoints: deployment.new_group_media_endpoints,
            group_image_endpoint: deployment.group_image_endpoint,
            profile_image_endpoint: deployment.profile_image_endpoint,
            open_ranking: deployment.open_ranking.map(|provider| OpenRankingProvider {
                search_endpoint: provider.search_endpoint,
                profile_relays: provider.profile_relays,
            }),
            key_package_client_preference: KeyPackageClientPreference {
                preferred: deployment.key_package_preferred_clients,
                last: deployment.key_package_last_clients,
            },
            moderation_label_namespace: deployment.moderation_label_namespace,
            keychain_service: deployment.keychain_service,
        }
        .normalize()
    }
}

/// White Noise's deployment as this build compiled it: the preset, with a
/// build-time `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` list over its new-group
/// media servers when one was set. A host that passes no deployment gets
/// these values until the neutral default lands.
#[uniffi::export]
pub fn marmot_deployment_white_noise() -> MarmotDeploymentFfi {
    marmot_app::MarmotAppConfig::white_noise().deployment.into()
}

/// No deployment services: every list empty, every option unset, and the
/// neutral keychain service `org.marmot-protocol.mdk`. Until the neutral
/// default lands, an empty new-group media list or an unset group-image or
/// profile-image server still falls back to White Noise's.
#[uniffi::export]
pub fn marmot_deployment_neutral() -> MarmotDeploymentFfi {
    MarmotDeployment::neutral().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_round_trip_through_the_record() {
        let white_noise = marmot_app::MarmotAppConfig::white_noise().deployment;
        assert_eq!(
            MarmotDeployment::from(marmot_deployment_white_noise()),
            white_noise
        );
        assert_eq!(
            MarmotDeployment::from(marmot_deployment_neutral()),
            MarmotDeployment::neutral()
        );
    }

    #[test]
    fn the_white_noise_record_keeps_the_default_keychain() {
        assert_eq!(
            marmot_deployment_white_noise().keychain_service,
            marmot_account::DEFAULT_KEYCHAIN_SERVICE_NAME
        );
    }

    #[test]
    fn blank_values_from_a_host_count_as_unset() {
        let deployment = MarmotDeployment::from(MarmotDeploymentFfi {
            group_image_endpoint: Some(" ".into()),
            open_ranking: Some(OpenRankingProviderFfi {
                search_endpoint: "https://rank.example".into(),
                profile_relays: Vec::new(),
            }),
            keychain_service: String::new(),
            ..marmot_deployment_neutral()
        });
        assert_eq!(deployment.group_image_endpoint, None);
        assert_eq!(deployment.open_ranking, None);
        assert_eq!(
            deployment.keychain_service,
            marmot_app::NEUTRAL_KEYCHAIN_SERVICE_NAME
        );
    }
}
