//! Adopted `quic://` broker-candidate parsing.

use std::net::IpAddr;

/// Maximum byte length of one complete kind-1200 `broker` tag value.
pub const QUIC_CANDIDATE_MAX_LEN: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicCandidate {
    original: String,
    authority: String,
    host: String,
    port: u16,
}

impl QuicCandidate {
    /// Parse and validate one complete candidate value. The authority ends at
    /// the first `/`, `?`, or `#`; the suffix is deliberately ignored.
    pub fn parse(candidate: &str) -> Result<Self, QuicCandidateError> {
        Self::parse_bytes(candidate.as_bytes())
    }

    /// Byte-oriented entry point so callers decoding untrusted tag bytes can
    /// enforce UTF-8 before constructing a `String`.
    pub fn parse_bytes(candidate: &[u8]) -> Result<Self, QuicCandidateError> {
        if candidate.len() > QUIC_CANDIDATE_MAX_LEN {
            return Err(QuicCandidateError::TooLong(candidate.len()));
        }
        let candidate =
            std::str::from_utf8(candidate).map_err(|_| QuicCandidateError::InvalidUtf8)?;
        let rest = candidate
            .strip_prefix("quic://")
            .ok_or(QuicCandidateError::InvalidScheme)?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.is_empty() {
            return Err(QuicCandidateError::MissingAuthority);
        }

        let (host, port_text) = if let Some(bracketed) = authority.strip_prefix('[') {
            let close = bracketed
                .find(']')
                .ok_or(QuicCandidateError::InvalidAuthority)?;
            let host = &bracketed[..close];
            let suffix = &bracketed[close + 1..];
            let port = suffix
                .strip_prefix(':')
                .filter(|port| !port.is_empty())
                .ok_or(QuicCandidateError::MissingPort)?;
            if suffix[1..].contains(':') || host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(QuicCandidateError::InvalidAuthority);
            }
            (host, port)
        } else {
            let (host, port) = authority
                .rsplit_once(':')
                .ok_or(QuicCandidateError::MissingPort)?;
            if host.is_empty() || host.contains(':') || port.is_empty() {
                return Err(QuicCandidateError::InvalidAuthority);
            }
            validate_unbracketed_host(host)?;
            (host, port)
        };
        let port = port_text
            .parse::<u16>()
            .map_err(|_| QuicCandidateError::InvalidPort)?;

        Ok(Self {
            original: candidate.to_owned(),
            authority: authority.to_owned(),
            host: host.to_owned(),
            port,
        })
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Candidate host used for TLS identity selection. DNS names remain DNS
    /// names; IP literals remain IP literals.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn ip_literal(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

fn validate_unbracketed_host(host: &str) -> Result<(), QuicCandidateError> {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(QuicCandidateError::InvalidHost);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QuicCandidateError {
    #[error("QUIC candidate is not valid UTF-8")]
    InvalidUtf8,
    #[error("QUIC candidate exceeds 512 bytes: {0}")]
    TooLong(usize),
    #[error("QUIC candidate must use the quic:// scheme")]
    InvalidScheme,
    #[error("QUIC candidate is missing an authority")]
    MissingAuthority,
    #[error("QUIC candidate authority is invalid")]
    InvalidAuthority,
    #[error("QUIC candidate host is invalid")]
    InvalidHost,
    #[error("QUIC candidate is missing a port")]
    MissingPort,
    #[error("QUIC candidate port is invalid")]
    InvalidPort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_candidate_length_and_utf8_are_enforced() {
        let prefix = "quic://a:1#";
        let one = "x";
        assert!(QuicCandidate::parse(one).is_err());
        let candidate_512 = format!(
            "{prefix}{}",
            "x".repeat(QUIC_CANDIDATE_MAX_LEN - prefix.len())
        );
        assert_eq!(candidate_512.len(), 512);
        assert!(QuicCandidate::parse(&candidate_512).is_ok());
        let candidate_513 = format!("{candidate_512}x");
        assert_eq!(
            QuicCandidate::parse(&candidate_513),
            Err(QuicCandidateError::TooLong(513))
        );
        assert_eq!(
            QuicCandidate::parse_bytes(&[0xff]),
            Err(QuicCandidateError::InvalidUtf8)
        );
    }

    #[test]
    fn suffixes_are_ignored_after_authority() {
        for suffix in ["/path", "?query", "#fragment", "/path?query#fragment"] {
            let parsed = QuicCandidate::parse(&format!("quic://broker.example:443{suffix}"))
                .expect("candidate");
            assert_eq!(parsed.authority(), "broker.example:443");
            assert_eq!(parsed.host(), "broker.example");
            assert_eq!(parsed.port(), 443);
        }
    }

    #[test]
    fn dns_ipv4_and_bracketed_ipv6_are_distinguished() {
        let dns = QuicCandidate::parse("quic://broker.example:443").unwrap();
        assert_eq!(dns.ip_literal(), None);
        let ipv4 = QuicCandidate::parse("quic://192.0.2.1:443").unwrap();
        assert_eq!(ipv4.ip_literal(), Some("192.0.2.1".parse().unwrap()));
        let ipv6 = QuicCandidate::parse("quic://[2001:db8::1]:443").unwrap();
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert_eq!(ipv6.ip_literal(), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn malformed_scheme_authority_port_and_ipv6_are_rejected() {
        for candidate in [
            "https://broker.example:443",
            "quic://",
            "quic://broker.example",
            "quic://broker.example:nope",
            "quic://broker..example:443",
            "quic://2001:db8::1:443",
            "quic://[2001:db8::1",
            "quic://[2001:db8::1]",
            "quic://[not-v6]:443",
        ] {
            assert!(
                QuicCandidate::parse(candidate).is_err(),
                "accepted {candidate}"
            );
        }
    }
}
