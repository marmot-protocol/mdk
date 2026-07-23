//! QUIC broker candidate parsing, address resolution, and trust selection.

use std::net::SocketAddr;

use cgka_traits::app_components::{is_loopback_candidate_host, reject_non_public_socket_addr};
use transport_quic_broker::BrokerServerTrust;

use crate::error::ConnectorError;
use crate::with_control_operation_timeout;

#[derive(Clone, Debug)]
pub(crate) struct ParsedQuicCandidate {
    pub(crate) original: String,
    pub(crate) authority: String,
    pub(crate) server_name: String,
}

pub(crate) fn first_quic_candidate(candidates: &[String]) -> Result<String, ConnectorError> {
    candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .map(|candidate| candidate.trim().to_owned())
        .ok_or_else(|| ConnectorError::Stream("stream begin requires a quic:// candidate".into()))
}

pub(crate) fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, ConnectorError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(ConnectorError::Stream(format!(
            "invalid QUIC candidate: {trimmed}"
        )));
    };
    // Per transports/quic.md a receiver MUST ignore any path, query, or
    // fragment after the authority; the authority ends at the first of '/',
    // '?', or '#'. Mirror the app/CLI parsers so this connector accepts the
    // same candidates the rest of the stack does.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(ConnectorError::Stream(format!(
            "invalid QUIC candidate: {trimmed}"
        )));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        original: trimmed.to_owned(),
        authority: authority.to_owned(),
        server_name,
    })
}

/// Resolve an agent-supplied `quic://` candidate to a socket address, running
/// the result through the shared dial-safety gate. `StreamBegin.quic_candidates`
/// is fully agent-controlled (a prompt-injected gateway can supply arbitrary
/// authorities), so without the explicit `allow_local_endpoint` dev opt-in a
/// candidate that resolves to loopback, private, link-local, CGNAT, or any
/// other non-public range is rejected before any QUIC handshake (SSRF
/// hardening; see `docs/marmot-architecture/overview/dial-safety.md`). The
/// returned address is the one the QUIC endpoint connects to, so the validated
/// address and the dialed address cannot diverge.
pub(crate) async fn resolve_quic_candidate_addr(
    candidate: &ParsedQuicCandidate,
    allow_local_endpoint: bool,
) -> Result<SocketAddr, ConnectorError> {
    let mut addrs = with_control_operation_timeout(
        "quic_candidate_dns_lookup",
        tokio::net::lookup_host(&candidate.authority),
    )
    .await?
    .map_err(|err| {
        ConnectorError::Stream(format!(
            "failed to resolve QUIC candidate {}: {err}",
            candidate.original
        ))
    })?;
    let addr = addrs.next().ok_or_else(|| {
        ConnectorError::Stream(format!("invalid QUIC candidate: {}", candidate.original))
    })?;
    reject_non_public_socket_addr(addr, allow_local_endpoint).map_err(|_| {
        ConnectorError::Stream(format!(
            "QUIC candidate resolved to a non-public address: {}",
            candidate.original
        ))
    })?;
    Ok(addr)
}

pub(crate) fn candidate_server_name(authority: &str) -> Result<String, ConnectorError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(ConnectorError::Stream(format!(
                "invalid QUIC candidate authority: {authority}"
            )));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            ConnectorError::Stream(format!("invalid QUIC candidate authority: {authority}"))
        })
}

/// Select TLS trust for a broker candidate from configuration and the LITERAL
/// candidate host, never from a resolved address. `InsecureLocal` (skip cert
/// verification) requires both the explicit `allow_insecure_local` dev opt-in
/// (`AgentConnectorConfig::allow_insecure_local_broker`, off by default) and a
/// candidate whose host is a literal loopback; a hostname that merely RESOLVES
/// to loopback keeps normal verification, so an agent-supplied candidate can
/// never downgrade trust through DNS. The broker client's
/// `InsecureLocalRequiresLoopback` check remains as the resolved-address
/// backstop behind this gate.
pub(crate) fn broker_trust_for_candidate(
    candidate_host: &str,
    allow_insecure_local: bool,
) -> BrokerServerTrust {
    if allow_insecure_local && is_loopback_candidate_host(candidate_host) {
        BrokerServerTrust::InsecureLocal
    } else {
        BrokerServerTrust::Platform
    }
}
