#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use marmot_terminal_harness::{
    DEFAULT_MAX_REPLY_BYTES, HarnessError, MARMOT_MESSAGE_BYTES_CEILING, Result,
};

use crate::pi::PiBackend;

const DEFAULT_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_PENDING_PER_GROUP: usize = 4;
const MIN_REPLY_BYTES: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    socket: PathBuf,
    auth_token: Option<String>,
    allowed_senders: HashSet<String>,
    account_id_hex: Option<String>,
    pi_bin: String,
    pi_session_dir: PathBuf,
    timeout: Duration,
    idle_timeout: Duration,
    request_timeout: Duration,
    max_reply_bytes: usize,
    max_pending_per_group: usize,
    state_path: PathBuf,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, &str)]) -> Result<Self> {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        Self::from_lookup(|name| map.get(name).map(|value| (*value).to_owned()))
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let home = lookup("MARMOT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs_home().join(".marmot-agents").join("pi"));
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
        let allowed_raw = lookup("WN_PI_ALLOWED_SENDERS_HEX").ok_or_else(|| {
            config_error(
                "WN_PI_ALLOWED_SENDERS_HEX must contain at least one 64-character hex sender id",
            )
        })?;
        let allowed_senders = parse_hex_csv("WN_PI_ALLOWED_SENDERS_HEX", &allowed_raw)?;
        let account_id_hex = lookup("WN_PI_ACCOUNT_ID_HEX")
            .or_else(|| lookup("MARMOT_ACCOUNT_ID_HEX"))
            .map(|value| normalize_hex("WN_PI_ACCOUNT_ID_HEX", &value))
            .transpose()?;
        if lookup("WN_PI_ACTIVATION").as_deref().unwrap_or("always") != "always" {
            return Err(config_error(
                "WN_PI_ACTIVATION currently supports only `always`",
            ));
        }
        let pi_bin = lookup("WN_PI_BIN").unwrap_or_else(|| "pi".to_owned());
        if pi_bin.trim().is_empty() {
            return Err(config_error("WN_PI_BIN must not be empty"));
        }
        let pi_session_dir = lookup("WN_PI_SESSION_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("dev").join("pi-sessions"));
        let timeout = Duration::from_secs(parse_u64(
            lookup("WN_PI_TIMEOUT_SECS"),
            DEFAULT_TIMEOUT_SECS,
            "WN_PI_TIMEOUT_SECS",
        )?);
        let idle_timeout = Duration::from_secs(parse_u64(
            lookup("WN_PI_IDLE_TIMEOUT_SECS"),
            DEFAULT_IDLE_TIMEOUT_SECS,
            "WN_PI_IDLE_TIMEOUT_SECS",
        )?);
        let request_timeout = Duration::from_secs(parse_u64(
            lookup("WN_PI_REQUEST_TIMEOUT_SECS"),
            DEFAULT_REQUEST_TIMEOUT_SECS,
            "WN_PI_REQUEST_TIMEOUT_SECS",
        )?);
        let max_reply_bytes = parse_usize(
            lookup("WN_PI_MAX_REPLY_BYTES"),
            DEFAULT_MAX_REPLY_BYTES,
            "WN_PI_MAX_REPLY_BYTES",
        )?;
        if !(MIN_REPLY_BYTES..=MARMOT_MESSAGE_BYTES_CEILING).contains(&max_reply_bytes) {
            return Err(config_error(format!(
                "WN_PI_MAX_REPLY_BYTES must be between {MIN_REPLY_BYTES} and {MARMOT_MESSAGE_BYTES_CEILING}"
            )));
        }
        let max_pending_per_group = parse_usize(
            lookup("WN_PI_MAX_PENDING_PER_GROUP"),
            DEFAULT_MAX_PENDING_PER_GROUP,
            "WN_PI_MAX_PENDING_PER_GROUP",
        )?;
        if max_pending_per_group == 0 {
            return Err(config_error(
                "WN_PI_MAX_PENDING_PER_GROUP must be greater than zero",
            ));
        }
        let state_path = lookup("WN_PI_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                lookup("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| dirs_home().join(".local").join("state"))
                    .join("wn-pi")
                    .join("sessions.json")
            });
        Ok(Self {
            socket,
            auth_token,
            allowed_senders,
            account_id_hex,
            pi_bin,
            pi_session_dir,
            timeout,
            idle_timeout,
            request_timeout,
            max_reply_bytes,
            max_pending_per_group,
            state_path,
        })
    }

    pub(crate) fn into_harness(self) -> (marmot_terminal_harness::Config, PiBackend) {
        let backend = PiBackend {
            bin: self.pi_bin,
            session_dir: self.pi_session_dir,
        };
        let config = marmot_terminal_harness::Config {
            socket: self.socket,
            auth_token: self.auth_token,
            allowed_senders: self.allowed_senders,
            account_id_hex: self.account_id_hex,
            request_timeout: self.request_timeout,
            max_reply_bytes: self.max_reply_bytes,
            max_pending_per_group: self.max_pending_per_group,
            state_path: self.state_path,
            backend_timeout: self.timeout,
            backend_idle_timeout: self.idle_timeout,
            display_name: "Pi",
            reply_prefix: "wn-pi",
            bin_env_name: "WN_PI_BIN",
        };
        (config, backend)
    }
}

fn dirs_home() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

fn parse_hex_csv(name: &'static str, raw: &str) -> Result<HashSet<String>> {
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

fn normalize_hex(name: &'static str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(config_error(format!(
            "{name} entries must be 64-character hex ids"
        )))
    }
}

fn parse_u64(raw: Option<String>, default: u64, name: &'static str) -> Result<u64> {
    raw.map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| config_error(format!("{name} must be an integer")))
    })
}

fn parse_usize(raw: Option<String>, default: usize, name: &'static str) -> Result<usize> {
    raw.map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| config_error(format!("{name} must be an integer")))
    })
}

fn config_error(message: impl Into<String>) -> HarnessError {
    HarnessError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn defaults_are_isolated_and_match_terminal_harness_limits() {
        let config = Config::from_pairs(&[("WN_PI_ALLOWED_SENDERS_HEX", SENDER)]).unwrap();
        assert!(
            config
                .socket
                .ends_with(".marmot-agents/pi/dev/wn-agent.sock")
        );
        assert!(
            config
                .pi_session_dir
                .ends_with(".marmot-agents/pi/dev/pi-sessions")
        );
        assert_eq!(config.max_reply_bytes, DEFAULT_MAX_REPLY_BYTES);
        assert_eq!(config.timeout, Duration::from_secs(3600));
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
    }

    #[test]
    fn rejects_missing_sender_and_invalid_activation() {
        assert!(Config::from_pairs(&[]).is_err());
        assert!(
            Config::from_pairs(&[
                ("WN_PI_ALLOWED_SENDERS_HEX", SENDER),
                ("WN_PI_ACTIVATION", "mention")
            ])
            .is_err()
        );
    }
}
