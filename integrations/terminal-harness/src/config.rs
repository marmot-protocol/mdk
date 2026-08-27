use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use crate::{
    ArtifactExportConfig, ArtifactExportGrant, Config, DEFAULT_MAX_ATTACHMENT_BYTES,
    DEFAULT_MAX_ATTACHMENTS, DEFAULT_MAX_REPLY_BYTES, HarnessError, MARMOT_MESSAGE_BYTES_CEILING,
    Result,
};

const DEFAULT_BACKEND_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_BACKEND_IDLE_TIMEOUT_SECS: u64 = 120;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_PENDING_PER_GROUP: usize = 4;
const MIN_REPLY_BYTES: usize = 4;

/// Operator intent for backend approval and isolation behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionProfile {
    /// Add no connector-owned execution-policy overrides.
    #[default]
    Inherit,
    /// Avoid interactive approvals while preserving hard denies and isolation.
    Autonomous,
    /// Request the backend's broadest non-interactive execution mode.
    Unrestricted,
}

impl ExecutionProfile {
    /// Stable environment and diagnostic value for this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Autonomous => "autonomous",
            Self::Unrestricted => "unrestricted",
        }
    }
}

impl fmt::Display for ExecutionProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ExecutionProfile {
    type Err = HarnessError;

    fn from_str(raw: &str) -> Result<Self> {
        match raw.trim() {
            "inherit" => Ok(Self::Inherit),
            "autonomous" => Ok(Self::Autonomous),
            "unrestricted" => Ok(Self::Unrestricted),
            _ => Err(config_error(
                "MARMOT_HARNESS_EXECUTION_PROFILE must be `inherit`, `autonomous`, or `unrestricted`",
            )),
        }
    }
}

/// Connector-specific names and defaults used by the shared environment parser.
#[derive(Clone, Copy, Debug)]
pub struct ConfigSpec {
    /// Connector environment prefix, such as `WN_PI`.
    pub env_prefix: &'static str,
    /// Directory name below `$HOME/.marmot-agents`.
    pub default_home_name: &'static str,
    /// Backend command used when no override is configured.
    pub default_bin: &'static str,
    /// Lowercase backend name for user-visible failures.
    pub display_name: &'static str,
    /// Harness identity for replies and control request ids.
    pub reply_prefix: &'static str,
    /// Backend binary environment variable.
    pub bin_env_name: &'static str,
    /// Account environment variable.
    pub account_env_name: &'static str,
    /// Optional historical sender-list alias.
    pub legacy_allowed_senders_env: Option<&'static str>,
}

/// Shared configuration plus backend values needed by a connector crate.
#[derive(Clone)]
pub struct LoadedConfig {
    /// Validated shared bridge configuration.
    pub harness: Config,
    /// Connector's Marmot home.
    pub home: PathBuf,
    /// Backend command or absolute binary path.
    pub bin: String,
}

impl fmt::Debug for LoadedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedConfig")
            .field("harness", &self.harness)
            .finish_non_exhaustive()
    }
}

/// Loads shared connector configuration from a caller-provided lookup function.
pub fn load_config_with(
    spec: ConfigSpec,
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> Result<LoadedConfig> {
    let env_name = |suffix: &str| format!("{}_{}", spec.env_prefix, suffix);
    let user_home = lookup("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| config_error("$HOME is not set"))?;
    let home = lookup("MARMOT_HOME").map(PathBuf::from).unwrap_or_else(|| {
        user_home
            .clone()
            .join(".marmot-agents")
            .join(spec.default_home_name)
    });
    let socket = lookup("MARMOT_AGENT_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("dev").join("wn-agent.sock"));
    let auth_token = match lookup("MARMOT_AGENT_AUTH_TOKEN_FILE") {
        Some(path) => {
            let token = fs::read_to_string(path)
                .map_err(|err| config_error(format!("failed to read auth token file: {err}")))?
                .trim()
                .to_owned();
            if token.is_empty() {
                return Err(config_error("auth token file is empty"));
            }
            Some(token)
        }
        None => lookup("MARMOT_AGENT_AUTH_TOKEN"),
    };

    let allowed_name = env_name("ALLOWED_SENDERS_HEX");
    let allowed_raw = lookup(&allowed_name)
        .or_else(|| spec.legacy_allowed_senders_env.and_then(&mut *lookup))
        .ok_or_else(|| {
            config_error(format!(
                "{allowed_name} must contain at least one 64-character hex sender id"
            ))
        })?;
    let allowed_senders = parse_hex_csv(&allowed_name, &allowed_raw)?;

    let account_name = env_name("ACCOUNT_ID_HEX");
    let account_id_hex = lookup(&account_name)
        .map(|value| (account_name.as_str(), value))
        .or_else(|| lookup("MARMOT_ACCOUNT_ID_HEX").map(|value| ("MARMOT_ACCOUNT_ID_HEX", value)))
        .map(|(name, value)| normalize_hex(name, &value))
        .transpose()?;

    let activation_name = env_name("ACTIVATION");
    if lookup(&activation_name)
        .as_deref()
        .unwrap_or("always")
        .trim()
        != "always"
    {
        return Err(config_error(format!(
            "{activation_name} currently supports only `always`"
        )));
    }

    let bin = lookup(spec.bin_env_name).unwrap_or_else(|| spec.default_bin.to_owned());
    if bin.trim().is_empty() {
        return Err(config_error(format!(
            "{} must not be empty",
            spec.bin_env_name
        )));
    }
    let execution_profile = lookup("MARMOT_HARNESS_EXECUTION_PROFILE")
        .as_deref()
        .unwrap_or("inherit")
        .parse()?;

    let backend_timeout = parse_positive_duration(
        lookup,
        &env_name("TIMEOUT_SECS"),
        DEFAULT_BACKEND_TIMEOUT_SECS,
    )?;
    let backend_idle_timeout = parse_positive_duration(
        lookup,
        &env_name("IDLE_TIMEOUT_SECS"),
        DEFAULT_BACKEND_IDLE_TIMEOUT_SECS,
    )?;
    let request_timeout = parse_positive_duration(
        lookup,
        &env_name("REQUEST_TIMEOUT_SECS"),
        DEFAULT_REQUEST_TIMEOUT_SECS,
    )?;
    let max_reply_name = env_name("MAX_REPLY_BYTES");
    let max_reply_bytes = parse_usize(
        lookup(&max_reply_name),
        DEFAULT_MAX_REPLY_BYTES,
        &max_reply_name,
    )?;
    if !(MIN_REPLY_BYTES..=MARMOT_MESSAGE_BYTES_CEILING).contains(&max_reply_bytes) {
        return Err(config_error(format!(
            "{max_reply_name} must be between {MIN_REPLY_BYTES} and {MARMOT_MESSAGE_BYTES_CEILING}"
        )));
    }
    let max_pending_name = env_name("MAX_PENDING_PER_GROUP");
    let max_pending_per_group = parse_usize(
        lookup(&max_pending_name),
        DEFAULT_MAX_PENDING_PER_GROUP,
        &max_pending_name,
    )?;
    if max_pending_per_group == 0 {
        return Err(config_error(format!(
            "{max_pending_name} must be greater than zero"
        )));
    }
    let max_attachments_name = env_name("MAX_ATTACHMENTS");
    let max_attachments = parse_usize(
        lookup(&max_attachments_name),
        DEFAULT_MAX_ATTACHMENTS,
        &max_attachments_name,
    )?;
    if max_attachments == 0 {
        return Err(config_error(format!(
            "{max_attachments_name} must be greater than zero"
        )));
    }
    let max_attachment_bytes_name = env_name("MAX_ATTACHMENT_BYTES");
    let max_attachment_bytes = parse_u64(
        lookup(&max_attachment_bytes_name),
        DEFAULT_MAX_ATTACHMENT_BYTES,
        &max_attachment_bytes_name,
    )?;
    if max_attachment_bytes == 0 {
        return Err(config_error(format!(
            "{max_attachment_bytes_name} must be greater than zero"
        )));
    }

    let state_name = env_name("STATE_PATH");
    let state_path = lookup(&state_name).map(PathBuf::from).unwrap_or_else(|| {
        lookup("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| user_home.join(".local").join("state"))
            .join(spec.reply_prefix)
            .join("sessions.json")
    });
    let artifact_enabled_name = env_name("ARTIFACT_EXPORTS_ENABLED");
    let artifact_enabled = parse_bool(
        lookup(&artifact_enabled_name),
        false,
        &artifact_enabled_name,
    )?;
    let artifact_grants_name = env_name("ARTIFACT_GRANTS_JSON");
    let artifact_grants = lookup(&artifact_grants_name)
        .map(|raw| parse_artifact_grants(&artifact_grants_name, &raw))
        .transpose()?
        .unwrap_or_default();
    if artifact_enabled && artifact_grants.is_empty() {
        return Err(config_error(format!(
            "{artifact_grants_name} must contain at least one exact group/root grant when artifact exports are enabled"
        )));
    }
    let artifact_max_count_name = env_name("ARTIFACT_MAX_COUNT");
    let artifact_max_count = parse_usize(
        lookup(&artifact_max_count_name),
        crate::artifacts::MAX_ARTIFACTS_PER_RESULT,
        &artifact_max_count_name,
    )?;
    if !(1..=crate::artifacts::MAX_ARTIFACTS_PER_RESULT).contains(&artifact_max_count) {
        return Err(config_error(format!(
            "{artifact_max_count_name} must be between 1 and {}",
            crate::artifacts::MAX_ARTIFACTS_PER_RESULT
        )));
    }
    let artifact_staging_root = lookup(&env_name("ARTIFACT_STAGING_ROOT"))
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("media-uploads"));
    let artifact_exports = ArtifactExportConfig::new(
        artifact_enabled,
        artifact_grants,
        artifact_staging_root,
        state_path.with_extension("artifact-outbox.json"),
    )
    .with_max_count(artifact_max_count);

    Ok(LoadedConfig {
        harness: Config {
            socket,
            auth_token,
            allowed_senders,
            account_id_hex,
            request_timeout,
            max_reply_bytes,
            max_pending_per_group,
            max_attachments,
            max_attachment_bytes,
            attachment_staging_root: home
                .join("tmp")
                .join(format!("{}-inbound-attachments", spec.reply_prefix)),
            state_path,
            backend_timeout,
            backend_idle_timeout,
            execution_profile,
            artifact_exports,
            spec,
        },
        home,
        bin,
    })
}

fn parse_positive_duration(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &str,
    default: u64,
) -> Result<Duration> {
    let seconds = parse_u64(lookup(name), default, name)?;
    if seconds == 0 {
        return Err(config_error(format!("{name} must be greater than zero")));
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_hex_csv(name: &str, raw: &str) -> Result<HashSet<String>> {
    let values = raw
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| normalize_hex(name, value))
        .collect::<Result<HashSet<_>>>()?;
    if values.is_empty() {
        return Err(config_error(format!("{name} contains no sender ids")));
    }
    Ok(values)
}

fn normalize_hex(name: &str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(config_error(format!(
            "{name} entries must be 64-character hex ids"
        )))
    }
}

fn parse_u64(raw: Option<String>, default: u64, name: &str) -> Result<u64> {
    raw.map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| config_error(format!("{name} must be an integer")))
    })
}

fn parse_usize(raw: Option<String>, default: usize, name: &str) -> Result<usize> {
    raw.map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| config_error(format!("{name} must be an integer")))
    })
}

fn parse_bool(raw: Option<String>, default: bool, name: &str) -> Result<bool> {
    raw.map_or(Ok(default), |value| match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(config_error(format!("{name} must be `true` or `false`"))),
    })
}

fn parse_artifact_grants(name: &str, raw: &str) -> Result<Vec<ArtifactExportGrant>> {
    let mut grants: Vec<ArtifactExportGrant> = serde_json::from_str(raw)
        .map_err(|_| config_error(format!("{name} must be a JSON array of artifact grants")))?;
    let mut groups = HashSet::new();
    for grant in &mut grants {
        let normalized = grant.group_id_hex.trim().to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() % 2 != 0
            || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(config_error(format!(
                "{name} grants require non-empty opaque hex group ids"
            )));
        }
        grant.group_id_hex = normalized;
        if !grant.export_root.is_absolute()
            || !(1..=crate::artifacts::MAX_ARTIFACT_GRANT_TTL_SECONDS).contains(&grant.ttl_seconds)
            || !groups.insert(grant.group_id_hex.clone())
        {
            return Err(config_error(format!(
                "{name} grants require a unique opaque hex group id, absolute export_root, and ttl_seconds between 1 and 86400"
            )));
        }
    }
    Ok(grants)
}

fn config_error(message: impl Into<String>) -> HarnessError {
    HarnessError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const SENDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SPEC: ConfigSpec = ConfigSpec {
        env_prefix: "WN_TEST",
        default_home_name: "test",
        default_bin: "test-agent",
        display_name: "test",
        reply_prefix: "wn-test",
        bin_env_name: "WN_TEST_BIN",
        account_env_name: "WN_TEST_ACCOUNT_ID_HEX",
        legacy_allowed_senders_env: None,
    };

    fn load(pairs: &[(&str, &str)]) -> Result<LoadedConfig> {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        load_config_with(SPEC, &mut |name| {
            map.get(name).map(|value| (*value).to_owned())
        })
    }

    #[test]
    fn shared_config_loads_defaults_and_prefixes() {
        let loaded = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
        ])
        .unwrap();
        assert_eq!(loaded.bin, "test-agent");
        assert_eq!(loaded.home, PathBuf::from("/home/test/.marmot-agents/test"));
        assert_eq!(loaded.harness.backend_timeout, Duration::from_secs(3600));
        assert_eq!(loaded.harness.max_reply_bytes, DEFAULT_MAX_REPLY_BYTES);
        assert_eq!(loaded.harness.max_attachments, DEFAULT_MAX_ATTACHMENTS);
        assert_eq!(
            loaded.harness.max_attachment_bytes,
            DEFAULT_MAX_ATTACHMENT_BYTES
        );
        assert_eq!(
            loaded.harness.attachment_staging_root,
            PathBuf::from("/home/test/.marmot-agents/test/tmp/wn-test-inbound-attachments")
        );
        assert_eq!(loaded.harness.execution_profile, ExecutionProfile::Inherit);
        assert!(!loaded.harness.artifact_exports.enabled());
        assert_eq!(
            loaded.harness.artifact_exports.max_count(),
            crate::artifacts::MAX_ARTIFACTS_PER_RESULT
        );
    }

    #[test]
    fn artifact_max_count_is_operator_configurable_within_transport_bound() {
        let base = [
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
        ];
        let mut configured = base.to_vec();
        configured.push(("WN_TEST_ARTIFACT_MAX_COUNT", "4"));
        assert_eq!(
            load(&configured)
                .unwrap()
                .harness
                .artifact_exports
                .max_count(),
            4
        );

        for invalid in ["0", "11"] {
            let mut values = base.to_vec();
            values.push(("WN_TEST_ARTIFACT_MAX_COUNT", invalid));
            let error = load(&values).unwrap_err();
            assert!(error.to_string().contains("ARTIFACT_MAX_COUNT"));
        }
    }

    #[test]
    fn artifact_exports_require_explicit_enablement_and_roots() {
        let base = [
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ARTIFACT_EXPORTS_ENABLED", "true"),
        ];
        assert!(load(&base).is_err());

        let loaded = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ARTIFACT_EXPORTS_ENABLED", "true"),
            (
                "WN_TEST_ARTIFACT_GRANTS_JSON",
                r#"[{"group_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","export_root":"/home/test/output","ttl_seconds":300}]"#,
            ),
        ])
        .unwrap();
        assert!(loaded.harness.artifact_exports.enabled());
        assert_eq!(loaded.harness.artifact_exports.grants().len(), 1);
    }

    #[test]
    fn artifact_exports_accept_16_byte_opaque_group_ids() {
        let loaded = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ARTIFACT_EXPORTS_ENABLED", "true"),
            (
                "WN_TEST_ARTIFACT_GRANTS_JSON",
                r#"[{"group_id_hex":"AABBCCDDEEFF00112233445566778899","export_root":"/home/test/output","ttl_seconds":300}]"#,
            ),
        ])
        .unwrap();
        assert_eq!(
            loaded.harness.artifact_exports.grants()[0].group_id_hex,
            "aabbccddeeff00112233445566778899"
        );
    }

    #[test]
    fn artifact_grant_ttl_defaults_to_one_hour_and_rejects_values_above_one_day() {
        let loaded = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ARTIFACT_EXPORTS_ENABLED", "true"),
            (
                "WN_TEST_ARTIFACT_GRANTS_JSON",
                r#"[{"group_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","export_root":"/home/test/output"}]"#,
            ),
        ])
        .unwrap();
        assert_eq!(
            loaded.harness.artifact_exports.grants()[0].ttl_seconds,
            crate::artifacts::DEFAULT_ARTIFACT_GRANT_TTL_SECONDS
        );

        assert!(
            load(&[
                ("HOME", "/home/test"),
                ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
                ("WN_TEST_ARTIFACT_EXPORTS_ENABLED", "true"),
                (
                    "WN_TEST_ARTIFACT_GRANTS_JSON",
                    r#"[{"group_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","export_root":"/home/test/output","ttl_seconds":86401}]"#,
                ),
            ])
            .is_err()
        );
    }

    #[test]
    fn artifact_exports_reject_ambiguous_boolean_values() {
        let error = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ARTIFACT_EXPORTS_ENABLED", "yes"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("ARTIFACT_EXPORTS_ENABLED"));
    }

    #[test]
    fn shared_config_parses_every_execution_profile() {
        for (raw, expected) in [
            ("inherit", ExecutionProfile::Inherit),
            ("autonomous", ExecutionProfile::Autonomous),
            ("unrestricted", ExecutionProfile::Unrestricted),
        ] {
            let loaded = load(&[
                ("HOME", "/home/test"),
                ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
                ("MARMOT_HARNESS_EXECUTION_PROFILE", raw),
            ])
            .unwrap();
            assert_eq!(loaded.harness.execution_profile, expected);
            assert_eq!(loaded.harness.execution_profile.as_str(), raw);
        }
    }

    #[test]
    fn shared_config_rejects_unknown_execution_profile() {
        let error = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("MARMOT_HARNESS_EXECUTION_PROFILE", "yolo"),
        ])
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("MARMOT_HARNESS_EXECUTION_PROFILE")
        );
    }

    #[test]
    fn shared_config_rejects_zero_timeouts_and_missing_home() {
        assert!(load(&[("WN_TEST_ALLOWED_SENDERS_HEX", SENDER)]).is_err());
        assert!(
            load(&[
                ("HOME", "/home/test"),
                ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
                ("WN_TEST_IDLE_TIMEOUT_SECS", "0"),
            ])
            .is_err()
        );
        for name in ["WN_TEST_MAX_ATTACHMENTS", "WN_TEST_MAX_ATTACHMENT_BYTES"] {
            assert!(
                load(&[
                    ("HOME", "/home/test"),
                    ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
                    (name, "0"),
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn shared_config_reports_account_source_name() {
        let error = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("MARMOT_ACCOUNT_ID_HEX", "invalid"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("MARMOT_ACCOUNT_ID_HEX"));
    }

    #[test]
    fn shared_config_trims_activation_for_compatibility() {
        let loaded = load(&[
            ("HOME", "/home/test"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ACTIVATION", " always\n"),
        ])
        .unwrap();
        assert_eq!(loaded.harness.spec.env_prefix, "WN_TEST");
    }

    #[test]
    fn loaded_config_debug_redacts_paths_binary_and_credentials() {
        let loaded = load(&[
            ("HOME", "/secret/home"),
            ("WN_TEST_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_TEST_ACCOUNT_ID_HEX", SENDER),
            ("WN_TEST_BIN", "/secret/bin/test-agent"),
            ("MARMOT_AGENT_AUTH_TOKEN", "secret-token"),
        ])
        .unwrap();
        let debug = format!("{loaded:?}");
        for secret in ["/secret", "secret-token", SENDER] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("auth_token_present: true"));
        assert!(debug.contains("account_id_present: true"));
        assert!(debug.contains("execution_profile: Inherit"));
    }
}
