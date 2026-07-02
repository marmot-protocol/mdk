//! QUIC broker candidate parsing, address resolution, and trust selection.

use std::net::SocketAddr;

use transport_quic_broker::BrokerServerTrust;

use crate::error::ConnectorError;

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
    let authority = rest.split('/').next().unwrap_or(rest);
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

pub(crate) async fn resolve_quic_candidate_addr(
    candidate: &ParsedQuicCandidate,
) -> Result<SocketAddr, ConnectorError> {
    let mut addrs = tokio::net::lookup_host(&candidate.authority)
        .await
        .map_err(|err| {
            ConnectorError::Stream(format!(
                "failed to resolve QUIC candidate {}: {err}",
                candidate.original
            ))
        })?;
    addrs.next().ok_or_else(|| {
        ConnectorError::Stream(format!("invalid QUIC candidate: {}", candidate.original))
    })
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

pub(crate) fn broker_trust_for_addr(broker_addr: SocketAddr) -> BrokerServerTrust {
    if broker_addr.ip().is_loopback() {
        BrokerServerTrust::InsecureLocal
    } else {
        BrokerServerTrust::Platform
    }
}
