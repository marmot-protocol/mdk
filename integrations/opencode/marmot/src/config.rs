use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{HarnessError, Result};

pub(crate) const DEFAULT_MAX_REPLY_BYTES: usize = 30_000;
pub(crate) const MARMOT_MESSAGE_BYTES_CEILING: usize = 60_000;
const DEFAULT_OPENCODE_TIMEOUT_SECS: u64 = 300;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_PENDING_PER_GROUP: usize = 4;
const MIN_REPLY_BYTES: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) socket: PathBuf,
    pub(crate) auth_token: Option<String>,
    pub(crate) allowed_senders: HashSet<String>,
    pub(crate) account_id_hex: Option<String>,
    pub(crate) opencode_bin: String,
    pub(crate) opencode_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) max_reply_bytes: usize,
    pub(crate) max_pending_per_group: usize,
    pub(crate) state_path: PathBuf,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(&str, &str)]) -> Result<Self> {
        let map: std::collections::HashMap<&str, &str> = pairs.iter().copied().collect();
        Self::from_lookup(|name| map.get(name).map(|value| (*value).to_owned()))
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let home = lookup("MARMOT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs_home().join(".marmot-agent"));
        let socket = lookup("MARMOT_AGENT_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("dev").join("wn-agent.sock"));

        let auth_token = match lookup("MARMOT_AGENT_AUTH_TOKEN_FILE") {
            Some(path) => {
                let token = fs::read_to_string(&path)
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

        let allowed_raw = lookup("WN_OPENCODE_ALLOWED_SENDERS_HEX")
            .or_else(|| lookup("WN_OPENCODE_ADMIN_HEX"))
            .ok_or_else(|| {
                config_error(
                    "WN_OPENCODE_ALLOWED_SENDERS_HEX must contain at least one 64-character hex sender id",
                )
            })?;
        let allowed_senders = parse_hex_csv("WN_OPENCODE_ALLOWED_SENDERS_HEX", &allowed_raw)?;

        let account_id_hex = lookup("WN_OPENCODE_ACCOUNT_ID_HEX")
            .or_else(|| lookup("MARMOT_ACCOUNT_ID_HEX"))
            .map(|value| normalize_hex("WN_OPENCODE_ACCOUNT_ID_HEX", &value))
            .transpose()?;

        let activation = lookup("WN_OPENCODE_ACTIVATION").unwrap_or_else(|| "always".to_owned());
        if activation.trim() != "always" {
            return Err(config_error(
                "WN_OPENCODE_ACTIVATION currently supports only `always`",
            ));
        }

        let opencode_bin = lookup("WN_OPENCODE_BIN").unwrap_or_else(|| "opencode".to_owned());
        if opencode_bin.trim().is_empty() {
            return Err(config_error("WN_OPENCODE_BIN must not be empty"));
        }

        let opencode_timeout = Duration::from_secs(parse_u64(
            lookup("WN_OPENCODE_TIMEOUT_SECS"),
            DEFAULT_OPENCODE_TIMEOUT_SECS,
            "WN_OPENCODE_TIMEOUT_SECS",
        )?);
        let request_timeout = Duration::from_secs(parse_u64(
            lookup("WN_OPENCODE_REQUEST_TIMEOUT_SECS"),
            DEFAULT_REQUEST_TIMEOUT_SECS,
            "WN_OPENCODE_REQUEST_TIMEOUT_SECS",
        )?);
        let max_reply_bytes = parse_usize(
            lookup("WN_OPENCODE_MAX_REPLY_BYTES"),
            DEFAULT_MAX_REPLY_BYTES,
            "WN_OPENCODE_MAX_REPLY_BYTES",
        )?;
        validate_reply_bytes(max_reply_bytes)?;
        let max_pending_per_group = parse_usize(
            lookup("WN_OPENCODE_MAX_PENDING_PER_GROUP"),
            DEFAULT_MAX_PENDING_PER_GROUP,
            "WN_OPENCODE_MAX_PENDING_PER_GROUP",
        )?;
        if max_pending_per_group == 0 {
            return Err(config_error(
                "WN_OPENCODE_MAX_PENDING_PER_GROUP must be greater than zero",
            ));
        }

        let state_path = lookup("WN_OPENCODE_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let base = lookup("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| dirs_home().join(".local").join("state"));
                base.join("wn-opencode").join("sessions.json")
            });

        Ok(Self {
            socket,
            auth_token,
            allowed_senders,
            account_id_hex,
            opencode_bin,
            opencode_timeout,
            request_timeout,
            max_reply_bytes,
            max_pending_per_group,
            state_path,
        })
    }
}

pub(crate) fn dirs_home() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

fn parse_hex_csv(name: &'static str, raw: &str) -> Result<HashSet<String>> {
    let mut values = HashSet::new();
    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        values.insert(normalize_hex(name, trimmed)?);
    }
    if values.is_empty() {
        return Err(config_error(format!("{name} contains no sender ids")));
    }
    Ok(values)
}

fn normalize_hex(name: &'static str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(config_error(format!(
            "{name} entries must be 64-character lowercase hex ids"
        )))
    }
}

fn parse_u64(raw: Option<String>, default: u64, name: &'static str) -> Result<u64> {
    match raw {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| config_error(format!("{name} must be an integer"))),
        None => Ok(default),
    }
}

fn parse_usize(raw: Option<String>, default: usize, name: &'static str) -> Result<usize> {
    match raw {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| config_error(format!("{name} must be an integer"))),
        None => Ok(default),
    }
}

fn validate_reply_bytes(max_reply_bytes: usize) -> Result<()> {
    if max_reply_bytes < MIN_REPLY_BYTES {
        return Err(config_error(format!(
            "WN_OPENCODE_MAX_REPLY_BYTES must be at least {MIN_REPLY_BYTES}"
        )));
    }
    if max_reply_bytes > MARMOT_MESSAGE_BYTES_CEILING {
        return Err(config_error(format!(
            "WN_OPENCODE_MAX_REPLY_BYTES must not exceed {MARMOT_MESSAGE_BYTES_CEILING}"
        )));
    }
    Ok(())
}

fn config_error(message: impl Into<String>) -> HarnessError {
    HarnessError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn config_uses_allowed_senders_and_30kb_default() {
        let cfg = Config::from_pairs(&[("WN_OPENCODE_ALLOWED_SENDERS_HEX", SENDER)]).unwrap();
        assert!(cfg.allowed_senders.contains(SENDER));
        assert_eq!(cfg.max_reply_bytes, DEFAULT_MAX_REPLY_BYTES);
    }

    #[test]
    fn config_accepts_legacy_admin_alias() {
        let cfg = Config::from_pairs(&[("WN_OPENCODE_ADMIN_HEX", SENDER)]).unwrap();
        assert!(cfg.allowed_senders.contains(SENDER));
    }

    #[test]
    fn config_rejects_reply_cap_above_marmot_ceiling() {
        let err = Config::from_pairs(&[
            ("WN_OPENCODE_ALLOWED_SENDERS_HEX", SENDER),
            ("WN_OPENCODE_MAX_REPLY_BYTES", "60001"),
        ])
        .unwrap_err();
        assert_eq!(err.privacy_safe_kind(), "config");
    }
}
